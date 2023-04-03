import json
import logging
import os
import traceback
from telnetlib import Telnet

import azure.functions as func
import requests
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from msrestazure.azure_exceptions import CloudError
from nacl.signing import VerifyKey

APPLICATION_PUBLIC_KEY = os.environ['APPLICATION_PUBLIC_KEY']
verify_key = VerifyKey(bytes.fromhex(APPLICATION_PUBLIC_KEY))
GROUP_NAME = 'Xion-Server-RG'

app = func.FunctionApp()

def verify(signature: str, timestamp: str, body: str) -> bool:
    try:
        verify_key.verify(f"{timestamp}{body}".encode(), bytes.fromhex(signature))
    except Exception as e:
        print(f"failed to verify request: {e}")
        return False
    
    return True

def get_credentials():
    subscription_id = os.environ['AZURE_SUBSCRIPTION_ID']
    credentials = ServicePrincipalCredentials(
        client_id=os.environ['AZURE_CLIENT_ID'], 
        secret=os.environ['AZURE_CLIENT_SECRET'],
        tenant=os.environ['AZURE_TENANT_ID']
    )
    return credentials, subscription_id

@app.function_name(name="XionServerIF")
@app.route(route="XionServerIF", auth_level=func.AuthLevel.ANONYMOUS, methods=['POST'], binding_arg_name='res')
@app.queue_output(arg_name="msg", queue_name="vmctrl-msg", connection="AzureWebJobsStorage")
def XionServerIF(req: func.HttpRequest, res: func.Out[func.HttpResponse], msg: func.Out[func.QueueMessage]):
    logging.info('HTTP trigger function がリクエストを受け取りました。')
    try: 
        req_body = req.get_json() 
    except ValueError: 
        logging.warning('Postリクエストに Body がありません。')
        pass 
    headers: dict = req.headers

    signature: str = headers.get('X-Signature-Ed25519')
    timestamp: str = headers.get('X-Signature-Timestamp')
    rawBody: str = req.get_body().decode('utf-8')
    if not verify(signature, timestamp, rawBody):
        res.set(func.HttpResponse('invalid request signature', status_code=401))
        logging.error('認証に失敗しました。')
        return 
    
    if req_body.get('type') == 1:
        logging.info('ping を受け取りました。')
        res_body_json = {
            "type": 1
            }
        res_body = json.dumps(res_body_json)
        res.set(func.HttpResponse(res_body, mimetype='application/json'))
        return 
    
    elif req_body.get('type') == 2:
        logging.info('command を受け取りました。')
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
                    logging.info('7dtd の start を受け取りました。')
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
                    logging.info('7dtd の stop を受け取りました。')
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
                    
        logging.warning('不明なコマンドを受け取りました。')
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
        logging.warning('不明なコマンドを受け取りました。')
        res_body = json.dumps(res_body_json)
        res.set(func.HttpResponse(res_body, mimetype='application/json'))
        return

@app.function_name(name="VMCtrl")
@app.queue_trigger(arg_name="msg", queue_name="vmctrl-msg", connection="AzureWebJobsStorage")  
def VMCtrl(msg: func.QueueMessage):
    logging.info('Queue trigger function がリクエストを受け取りました。')
    msg_body = json.loads(msg.get_body())

    vm_name = msg_body.get('vm-name')
    application_id = msg_body.get('application_id')
    interaction_token = msg_body.get('interaction_token')

    if msg_body.get('type') == "start":
        try:
            logging.info(f"{vm_name} を起動します。")
            credentials, subscription_id = get_credentials()
            compute_client = ComputeManagementClient(credentials, subscription_id)
            async_vm_start = compute_client.virtual_machines.start(
                GROUP_NAME, vm_name)
            async_vm_start.wait()
        except CloudError:
            res_body_json = {
            "type": 4, 
            "data": {
                "content": 'A VM operation failed:\n{}'.format(traceback.format_exc())
                }
            }
            logging.error('A VM operation failed:\n{}'.format(traceback.format_exc()))
        else:
            res_body_json = {
                "content": "7dtd server start successfully!"
            }
            logging.info(f"{vm_name} を起動しました。")
        finally:
            url = f"https://discord.com/api/v10/webhooks/{application_id}/{interaction_token}/messages/@original"
            requests.patch(url, json=res_body_json)
            return

    elif msg_body.get('type') == 'stop':
        password = os.environ['7DTD_TELNET_PASS']
        try:
            with Telnet("xion-7dtdserver.japaneast.cloudapp.azure.com", 8081, timeout=10) as tn:
                tn.read_until(b"Please enter password:")
                tn.write(password.encode('ascii') + b"\n")
                tn.write(b"shutdown\n")
        except:
            pass

        try:
            logging.info(f"{vm_name} を停止します。")
            credentials, subscription_id = get_credentials()
            compute_client = ComputeManagementClient(credentials, subscription_id)
            async_vm_stop = compute_client.virtual_machines.deallocate(
                GROUP_NAME, vm_name)
            async_vm_stop.wait()
        except CloudError:
            res_body_json = {
            "type": 4, 
            "data": {
                "content": 'A VM operation failed:\n{}'.format(traceback.format_exc())
                }
            }
            logging.error('A VM operation failed:\n{}'.format(traceback.format_exc()))
        else:
            res_body_json = {
                "content": "7dtd server stop successfully!"
            }
            logging.info(f"{vm_name} を停止しました。")
        finally:
            url = f"https://discord.com/api/v10/webhooks/{application_id}/{interaction_token}/messages/@original"
            requests.patch(url, json=res_body_json)
            return
    logging.warning('不明なコマンドを受け取りました。')
    return