import azure.functions as func
from nacl.signing import VerifyKey
import json
import os
import requests

APPLICATION_PUBLIC_KEY = os.environ['APPLICATION_PUBLIC_KEY']
verify_key = VerifyKey(bytes.fromhex(APPLICATION_PUBLIC_KEY))
VMCTRL_URL = "https://vmctrl.azurewebsites.net/api/vmctrl"

app = func.FunctionApp()

def verify(signature: str, timestamp: str, body: str) -> bool:
    try:
        verify_key.verify(f"{timestamp}{body}".encode(), bytes.fromhex(signature))
    except Exception as e:
        print(f"failed to verify request: {e}")
        return False
    
    return True

@app.function_name(name="XionServerIF")
@app.route(route="XionServerIF", auth_level=func.AuthLevel.ANONYMOUS, methods=['POST'], binding_arg_name='res')
@app.queue_output(arg_name="msg", queue_name="vmctrl-msg", connection="AzureWebJobsStorage")
def main(req: func.HttpRequest, res: func.Out[func.HttpResponse], msg: func.Out[func.QueueMessage]):
    try: 
        req_body = req.get_json() 
    except ValueError: 
        pass 
    headers: dict = req.headers

    signature: str = headers.get('X-Signature-Ed25519')
    timestamp: str = headers.get('X-Signature-Timestamp')
    rawBody: str = req.get_body().decode('utf-8')
    if not verify(signature, timestamp, rawBody):
        res.set(func.HttpResponse('invalid request signature', status_code=401))
        return 
    
    if req_body.get('type') == 1:
        res_body_json = {
            "type": 1
            }
        res_body = json.dumps(res_body_json)
        res.set(func.HttpResponse(res_body, mimetype='application/json'))
        return 
    
    elif req_body.get('type') == 2:
        res_body_json = {
            "type": 4, 
            "data": {
                "content": "unknown command"
                }
            }
        application_id = req_body.get('application_id')
        interaction_token = req_body.get('token')
        if req_body.get('data').get('name') == 'cxs':
            if req_body.get('data').get('options')[0].get('name') == '7dtd':
                if req_body.get('data').get('options')[0].get('options')[0].get('value') == 'start':
                    res_body_json = {
                        "type": 4, 
                        "data": {
                            "content": "7dtd server starting..."
                            }
                        }
                    vm_ctrl_json = {
                        "type": "start",
                        "vm-name": "7DaysToDie-VM",
                        "application_id": application_id,
                        "interaction_token": interaction_token
                    }
                    res_body = json.dumps(res_body_json)
                    vm_ctrl = json.dumps(vm_ctrl_json)
                    msg.set(vm_ctrl)
                    res.set(func.HttpResponse(res_body, mimetype='application/json'))
                    return
                
                elif req_body.get('data').get('options')[0].get('options')[0].get('value') == 'stop':
                    res_body_json = {
                        "type": 4, 
                        "data": {
                            "content": "7dtd server stopping..."
                            }
                        }
                    vm_ctrl_json = {
                        "type": "stop",
                        "vm-name": "7DaysToDie-VM",
                        "application_id": application_id,
                        "interaction_token": interaction_token
                    }
                    res_body = json.dumps(res_body_json)
                    vm_ctrl = json.dumps(vm_ctrl_json)
                    msg.set(vm_ctrl)
                    res.set(func.HttpResponse(res_body, mimetype='application/json'))
                    return
                    
        res_body = json.dumps(res_body_json)
        res.set(func.HttpResponse(res_body, mimetype='application/json'))
        return 
    
    else:
        res_body_json = {
            "type": 4, 
            "data": {
                "content": "unknown command"
                }
            }
        res_body = json.dumps(res_body_json)
        res.set(func.HttpResponse(res_body, mimetype='application/json'))
        return 