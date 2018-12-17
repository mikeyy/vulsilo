#!/usr/bin/env python

import fabric
import logging
import random
import time

from vultr import Vultr, VultrError
from namesilo import NameSilo

# DOMAINS TO SETUP
DOMAINS_FILE = "domains.txt"

# CATCH-ALL EMAIL DETAILS
FWD_TO_EMAIL = "YOUR_EMAIL"

# NAMESILO DETAILS
NAMESILO_API_KEY = "YOUR_API_KEY"

# VULTR DETAILS
VULTR_API_KEY = "YOUR_API_KEY"
VULTR_REGIONS = {'New Jersey, NY': 1, 'Chicago, IL': 2, 'London, GB': 8}
# $5 1 CPU 1024MB Mem 1000GB Bw
VULTR_PLAN_ID = 201
# Application
VULTR_OS_ID = 186
# Wordpress (Ubuntu 16.04 x64)
VULTR_APP_ID = 2

vultr = Vultr(VULTR_API_KEY)
namesilo = NameSilo(NAMESILO_API_KEY, live=True)


def available_plans():
    """This isn't right, it's missing a couple plans."""
    try:
        return vultr.plans.list()
    except VultrError as ex:
        logging.error('VultrError: %s', ex)


def create_instance(dcid, vpsplanid, osid, params):
    # create(self, dcid, vpsplanid, osid, params=None):
    try:
        response = vultr.server.create(dcid, vpsplanid, osid, params)
        return response['SUBID']
    except VultrError as ex:
        logging.error('VultrError: %s', ex)


def get_instance_details(serverID, wait_to_ready=False):
    while 1:
        serverList = vultr.server.list()
        if serverList[serverID]['server_state'] == u'ok':
            return serverList[serverID]
        elif not wait_to_ready:
            ignore = [u'0.0.0.0', u'none']
            if serverList[serverID]["main_ip"] not in ignore:
                return serverList[serverID]
        time.sleep(3)


def remove_dns_records(domain):
    data = namesilo.list_dns_records(
        domain=domain)
    if 'resource_record' in data:
        resource_records_list = data['resource_record']
        for records_list in resource_records_list:
            if isinstance(records_list, dict):
                namesilo.delete_dns_record(
                    domain=domain, rrid=records_list["record_id"])
            for records in records_list:
                if isinstance(records, dict):
                    namesilo.delete_dns_record(
                        domain=domain, rrid=records["record_id"])
                for record in records:
                    if isinstance(record, dict):
                        namesilo.delete_dns_record(
                            domain=domain, rrid=record["record_id"])


def add_dns_records(domain, address):
    subfixes = ['www', '']
    ttl = 7207
    for subfix in subfixes:
        namesilo.add_dns_record(
            domain=domain,
            rrtype='A',
            rrhost=subfix,
            rrvalue=address,
            rrttl=ttl)


def add_catch_all_email(domain, email):
    namesilo.add_email_forward(domain=domain, email="*", forward1=email)


def setup_ssh(host, domain, username, password):
    with fabric.Connection(
            host,
            user=username,
            connect_kwargs={"password": password}) as conn:
        commands = [
            "add-apt-repository ppa:certbot/certbot -y",
            "apt-get update",
            "apt-get install -y certbot python-certbot-nginx python-pip "\
            "python-pyasn1 python-pyasn1-modules",
            "echo '{} {} www.{}' >> /etc/hosts",
            "certbot --nginx -d {} -d www.{} --non-interactive "\
            "--agree-tos --email admin@{}".format(domain, domain, domain)]
        for command in commands:
            print(" - Running command `{}``".format(command))
            try:
                conn.sudo(command, hide=True)
            except Exception:
                pass


def parse_wordpress_login(subid):
    app_info = vultr.server.get_app_info(subid)["app_info"]
    for line in app_info.split("\n"):
        if 'User:' in line:
            username = line.split(': ')[1]
        if 'Pass:' in line:
            password = line.split(': ')[1]
            break
    return (username, password)


def main(domain):
    print("# Domain `{}`".format(domain))
    dcid_dict = random.choice(VULTR_REGIONS.keys())
    dcid = VULTR_REGIONS[dcid_dict]
    extra_params = {"APPID": VULTR_APP_ID}
    print("# Creating instance in {}".format(dcid_dict))
    SUBID = create_instance(dcid, VULTR_PLAN_ID, VULTR_OS_ID, extra_params)
    print("# Getting instance details")
    instance_details = get_instance_details(SUBID)
    main_ip = instance_details["main_ip"]
    print("# Instance assigned address {}".format(main_ip))
    default_password = instance_details["default_password"]
    print("# Registering domain {}".format(domain))
    namesilo.register_domain(domain=domain, years=1, private=1)
    print("# Removing default DNS records")
    remove_dns_records(domain=domain)
    print("# Adding VULTR instance to DNS records")
    add_dns_records(domain=domain, address=main_ip)
    print("# Adding catch-all to email forwarders")
    add_catch_all_email(domain=domain, email=FWD_TO_EMAIL)
    print("# Setting up SSL Certificate")
    setup_ssh(main_ip, domain, "root", default_password)
    print("# Getting Wordpress login details")
    wordpress_user, wordpress_pass = parse_wordpress_login(SUBID)
    print(
        "---\nInstance {} is now ready!\n\nDomain: {}\nWP User: {}\nWP Pass: {}"
        .format(SUBID, domain, wordpress_user, wordpress_pass))


domains = open(DOMAINS_FILE).read().strip().split("\n")
for domain in domains:
    main(domain)
