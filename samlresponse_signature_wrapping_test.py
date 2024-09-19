#############################################
# Test SAML logs for forged SAML Response
#   * CVE-2024-45409
#   * Based on ruby-saml patch: <https://github.com/SAML-Toolkits/ruby-saml/commit/4865d030cae9705ee5cdb12415c654c634093ae7>
#   * Assumes filtered Ruby / Rail log output
#############################################

import argparse
import base64
import libxml2
import logging
import os
import pathlib
import re

def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input", required=True, help="Location input file."
    )

    parser.add_argument(
        "--logging_level",
        required=False,
        help="Logging level.",
        default=logging.CRITICAL
        )

    return parser.parse_args()

#
def saml_response_forgery(saml_response_xml):
    document = libxml2.parseDoc(saml_response_xml)
    context = document.xpathNewContext()
    context.xpathRegisterNs("samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
    context.xpathRegisterNs("saml", "urn:oasis:names:tc:SAML:2.0:assertion")
    context.xpathRegisterNs("ds", "http://www.w3.org/2000/09/xmldsig#")

    sig_element = context.xpathEval("//ds:Signature")
    if len(sig_element) != 1:
        logging.critical(f"ERROR ds:Signature f{saml_response_xml}")
        return True

    logging.debug(f"ds:signature {sig_element[0]}")

    signed_info_element = context.xpathEval("/samlp:Response/ds:Signature[1]/ds:SignedInfo")
    if len(signed_info_element) != 1:
        logging.critical(f"ERROR ds:SignedInfo count {len(signed_info_element)} [{signed_info_element}] {saml_response_xml}")
        return True

    logging.debug(f"ds:SignedInfo {signed_info_element}")

    # extract_signed_element_id
    reference_id = context.xpathEval("//ds:Signature/ds:SignedInfo/ds:Reference/@URI")
    if len(reference_id) != 1:
        logging.critical(f"ERROR URI {len(reference_id)} {saml_response_xml}")
        return True

    logging.debug(f"ds:Reference {reference_id[0]}")

    reference_element = context.xpathEval("/samlp:Response/ds:Signature[1]/ds:SignedInfo[1]/ds:Reference")
    if len(reference_element) != 1:
        logging.critical(f"ERROR ds:Reference count {len(reference_element)} [{reference_element}] {saml_response_xml}")
        return True

    logging.debug(f"ds:Reference {reference_element}")

    # multiple ds:Reference
    reference_element = context.xpathEval("//ds:Reference")
    if len(reference_element) != 1:
        logging.critical(f"ERROR //ds:Reference  count {len(reference_element)} {saml_response_xml}")
        return True

    logging.debug(f"ds:Reference {reference_id[0]}")

    # remove XML ID reference char from ID
    id = reference_id[0].content.lstrip("#") if reference_id else None
    logging.debug(f"ID: {id}")

    reference_nodes = context.xpathEval(f"//*[@ID='{id}']")
    if len(reference_nodes) != 1:
        logging.critical(f"ERROR ID count {len(reference_nodes)} [{reference_nodes}] {saml_response_xml}")
        return True

    document.freeDoc()

    return False


#
def process(input_file):

    #
    for counter, line in enumerate(input_file):
        # logging.info(f"{line}")
        # return only SAML response of the log entry
        matches = re.findall(r'"SAMLResponse"=>"(.*?)"', line)
        if matches and len(matches) ==1 :
            saml_response = matches[0]
            saml_response_xml = base64.b64decode(saml_response)
            forgery = saml_response_forgery(saml_response_xml.decode('utf-8'))
            if forgery:
                print(counter)
                logging.critical(f"SAML forgery detected [{counter}] [{line}]")

        else:
            logging.error(f"Malformed SAMLResponse log [{counter}] [{line}]")


def main():

    args = parse_args()

    logging.basicConfig(level=args.logging_level)

    pathlib.Path(os.path.dirname(args.input)).mkdir(parents=True, exist_ok=True)
    with open(args.input, "rt", encoding="utf-8", newline="") as input_file:
        process(input_file)


if __name__ == "__main__":
    main()