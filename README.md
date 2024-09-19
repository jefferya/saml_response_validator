# SAML Response Validator

Test the SAML Response for forgery attempts. The main usecase is:

* CVE-2024-45409 Ruby-SAML SAML Response Forgery Vulnerability

## Requriments

* Python 3.10+ 

## Usage

* Filter application log files from a Ruby application
  * `grep SAMLResponse x.log > ${x}`
* Run test
  * `python3 samlresponse_signature_wrapping_test.py --input ${x}` 


## To test

`pytest tests/test.py`
