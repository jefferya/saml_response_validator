"""
Test
"""

import os
import sys

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)  # noqa:E402

import samlresponse_signature_wrapping_test as sr


# https://docs.pytest.org/en/latest/how-to/logging.html#caplog-fixture
def test_samlrepsonse_valid(caplog):

    with open("tests/assets/fixtures/test_samlresponse_valid.xml", "r", newline="") as file_fd:
        xml = file_fd.read()
    print(xml)
    ret = sr.saml_response_forgery(xml)
    assert ret == False
    for record in caplog.records:
        assert record.levelname != "ERROR"
        assert record.levelname != "CRITICAL"


def test_single_signature(caplog):

    with open("tests/assets/fixtures/test_single_signature_error.xml", "r", newline="") as file_fd:
        xml = file_fd.read()
    print(xml)
    ret = sr.saml_response_forgery(xml)
    assert ret == True
    for record in caplog.records:
        assert record.levelname == "CRITICAL"
    assert "ERROR ds:Signature" in caplog.text

def test_single_signedinfo(caplog):

    # signed_info_element = context.xpathEval("/samlp:Response/ds:Signature[1]/ds:SignedInfo")
    with open("tests/assets/fixtures/test_single_signedInfo_error.xml", "r", newline="") as file_fd:
        xml = file_fd.read()
    ret = sr.saml_response_forgery(xml)
    assert ret == True
    for record in caplog.records:
        assert record.levelname == "CRITICAL"
    assert "ERROR ds:SignedInfo" in caplog.text

def test_single_reference(caplog):

    # reference_element = context.xpathEval("/samlp:Response/ds:Signature[1]/ds:SignedInfo[1]/ds:Reference")
    with open("tests/assets/fixtures/test_single_reference_error.xml", "r", newline="") as file_fd:
        xml = file_fd.read()
    ret = sr.saml_response_forgery(xml)
    assert ret == True
    for record in caplog.records:
        assert record.levelname == "CRITICAL"
    assert "ERROR ds:Reference" in caplog.text

def test_single_uri(caplog):

    # reference_id = context.xpathEval("//ds:Signature/ds:SignedInfo/ds:Reference/@URI")
    with open("tests/assets/fixtures/test_single_uri_error.xml", "r", newline="") as file_fd:
        xml = file_fd.read()
    ret = sr.saml_response_forgery(xml)
    assert ret == True
    for record in caplog.records:
        assert record.levelname == "CRITICAL"
        print(record)
    assert "ERROR URI" in caplog.text

def test_single_reference_anywhere(caplog):
    # multiple ds:Reference reference_element = context.xpathEval("//ds:Reference")
    with open("tests/assets/fixtures/test_single_reference_anywhere_error.xml", "r", newline="") as file_fd:
        xml = file_fd.read()
    ret = sr.saml_response_forgery(xml)
    assert ret ==  True
    for record in caplog.records:
        assert record.levelname == "CRITICAL"
    assert "ERROR //ds:Reference" in caplog.text

def test_single_id(caplog):
    with open("tests/assets/fixtures/test_single_id_error.xml", "r", newline="") as file_fd:
        xml = file_fd.read()
    ret = sr.saml_response_forgery(xml)
    assert ret ==  True
    for record in caplog.records:
        assert record.levelname == "CRITICAL"
    assert "ERROR ID" in caplog.text
