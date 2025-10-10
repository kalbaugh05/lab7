from presidio_anonymizer.operators import Encrypt
from presidio_anonymizer.operators.aes_cipher import AESCipher
from presidio_anonymizer.entities import InvalidParamError
import pytest
from unittest import mock


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(
    mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

    assert anonymized_text == expected_anonymized_text


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(
        mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text",
                                        params={"key": b'1111111111111111'})

    assert anonymized_text == expected_anonymized_text


def test_given_verifying_an_valid_length_key_no_exceptions_raised():
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised():
    Encrypt().validate(params={"key": b'1111111111111111'})


def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})






@mock.patch.object(AESCipher, "is_valid_key_size")
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_is_valid_key_size):
    # Arrange: simulate invalid key size
    mock_is_valid_key_size.return_value = False

    # Act + Assert: expect InvalidParamError
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b"badkey"})

    # Verify the mock was used
    mock_is_valid_key_size.assert_called_once()



def test_operator_name():
    assert Encrypt().operator_name == "encrypt"

def test_operator_type():
    from presidio_anonymizer.operators import OperatorType
    assert Encrypt().operator_type == OperatorType.Anonymize
       

@pytest.mark.parametrize(
    "key",
    [
        "k"*16,  # 128 bits
        "k"*24,  # 192 bits
        "k"*32,  # 256 bits
        b"k"*16, # 128 bits bytes
        b"k"*24, # 192 bits bytes
        b"k"*32, # 256 bits bytes
    ]
)
def test_valid_keys(key):  # Must start with 'test_'
    from presidio_anonymizer.operators import Encrypt
    Encrypt().validate(params={"key": key})



    from presidio_anonymizer.operators.encrypt import Encrypt

class DummyEncrypt(Encrypt):
    operator_name = "encrypt"
    operator_type = "crypto"
