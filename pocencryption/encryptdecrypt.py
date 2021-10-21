import base64
import logging
from datetime import datetime

import boto3
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet
from .models import Datakeys

def decrypt_data_key(data_key_encrypted):
    """Decrypt an encrypted data key
    :param data_key_encrypted: Encrypted ciphertext data key.
    :return Plaintext base64-encoded binary data key as binary string
    :return None if error
    """
    # Decrypt the data key
    #print("In K cyperText {}" .format( data_key_encrypted))
    kms_client = boto3.client('kms')
    try:
        response = kms_client.decrypt(CiphertextBlob=data_key_encrypted)
    except ClientError as e:
        logging.error(e)
        return None
    # Return plaintext base64-encoded binary data key
    return base64.b64encode((response['Plaintext']))

def create_cmk(desc='Customer Master Key'):
    """Create a KMS Customer Master Key
    The created CMK is a Customer-managed key stored in AWS KMS.
    :param desc: key description
    :return Tuple(KeyId, KeyArn) where:
    KeyId: AWS globally-unique string ID
    KeyArn: Amazon Resource Name of the CMK
    :return Tuple(None, None) if error
    """
    # Create CMK
    kms_client = boto3.client('kms')
    try:
        response = kms_client.create_key(Description=desc)
    except ClientError as e:
        logging.error(e)
    return None, None
    # Return the key ID and ARN
    return response['KeyMetadata']['KeyId'], response['KeyMetadata']['Arn']

def create_data_key(cmk_id, key_spec='AES_256'):
    """Generate a data key to use when encrypting and decrypting data
    :param cmk_id: KMS CMK ID or ARN under which to generate and encrypt the
    data key.
    :param key_spec: Length of the data encryption key. Supported values:
    'AES_128': Generate a 128-bit symmetric key
    'AES_256': Generate a 256-bit symmetric key
    :return Tuple(EncryptedDataKey, PlaintextDataKey) where:
    EncryptedDataKey: Encrypted CiphertextBlob data key as binary string
    PlaintextDataKey: Plaintext base64-encoded data key as binary string
    :return Tuple(None, None) if error
    """
    # Create data key
    kms_client = boto3.client('kms')
    try:
        response = kms_client.generate_data_key(KeyId=cmk_id, KeySpec=key_spec)
        print(response)
    except ClientError as e:
        logging.error(e)
        return None, None
    # Return the encrypted and plaintext data key
    return response['CiphertextBlob'], base64.b64encode(response['Plaintext'])

def data_encrypt(data,cmk_id):
    """Encrypt data using an AWS KMS CMK
     :param data: data to encrypt
     :param cmk_id: AWS KMS CMK ID or ARN
     :return: encrypted data. Otherwise, False.
     """
    #data_key_encrypted, data_key_plaintext = create_data_key(cmk_id)
    data_key_encrypted = Datakeys.objects.all()[0].data_key
    #data_key_encrypted = datakeyObj.data_key
    #print("In E cyperText {}" .format( data_key_encrypted))
    data_key_plaintext = decrypt_data_key(data_key_encrypted)

    #print("In E cyperText {}" .format( data_key_encrypted))
    #print('IN E plainText {}' .format( data_key_plaintext))
    f = Fernet(data_key_plaintext)
    encrypted_data = f.encrypt(data.encode())
    #print('IN E plainText {}' .format( encrypted_data))
    return encrypted_data, data_key_encrypted


def data_decrypt(encrypted_data, data_key_encrypted):
    """Decrypt a data encrypted by data_encrypt()
     :param data: data to decrypt
     :return: True decrypted data . Otherwise, False.
     """
    #print("In D cyperText{}" .format( encrypted_data))

    data_key_plaintext = decrypt_data_key(data_key_encrypted)
    #print("IN D plainText{}" .format( data_key_plaintext))
    #print('IN D plainText {}' .format( encrypted_data))
    if data_key_plaintext is None:
        return False
    f = Fernet(data_key_plaintext)
    return f.decrypt(encrypted_data)


def retrieve_cmk(description):
    """Retrieve an existing KMS CMK based on its description"""

    # Retrieve a list of existing CMKs
    # If more than 100 keys exist, retrieve and process them in batches
    kms_client = boto3.client("kms")
    response = kms_client.list_keys()

    for cmk in response["Keys"]:
        key_info = kms_client.describe_key(KeyId=cmk["KeyArn"])
        if key_info["KeyMetadata"]["Description"] == description:
            return cmk["KeyId"], cmk["KeyArn"]

    # No matching CMK found
    return None, None

def savekey(data_key_encrypted):
    datakey = Datakeys(data_key =data_key_encrypted,
                       country_id = 'IN',
                       pub_date =datetime.today())
    datakey.save()
    return 'Saved suucessfully'

def createKeyFirstTime(cmk_id):
    data_key_encrypted, data_key_plaintext = create_data_key(cmk_id)
    print("In S cyperText {}" .format( data_key_encrypted))
    print('IN S plainText {}' .format( data_key_plaintext))
    savekey(data_key_encrypted)
