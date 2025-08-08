import io
import pickle
import boto3
import utils
from flask import request
from routing.upload.blueprint import blueprint

s3_client = boto3.client('s3')

def _unpickle_request_content():
    req_data = request.data
    sanitized_data = utils.clean(req_data)
    return pickle.loads(sanitized_data)

def _upload_to_s3(data):
    byte_data = io.BytesIO(data)
    s3_client.upload_fileobj(byte_data, 'foo', 'bar')

@blueprint.route('/upload', methods=['POST'])
def upload():
    unpickled_data = _unpickle_request_content()
    _upload_to_s3(unpickled_data)

    return 204
