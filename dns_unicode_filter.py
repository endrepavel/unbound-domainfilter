'''
- https://github.com/ohitz/unbound-domainfilter/blob/master/dns_filter.py

Install and configure:

- copy dns_unicode_filter.py to /etc/unbound/dns_unicode_filter.py

- if needed, change intercept_address

- change unbound.conf as follows:

  server:
    module-config: "python validator iterator"
  python:
    python-script: "/etc/unbound/dns_unicode_filter.py"

- restart unbound

'''

unicodefilter = "xn--"

intercept_address = "127.0.0.1"

def init(id, cfg):
    log_info("dns_unicode_filter.py: ")
    return True

def deinit(id):
    return True

def inform_super(id, qstate, superqstate, qdata):
    return True

def operate(id, event, qstate, qdata):

    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):

        # Check if hostname unicode.
        log_info("dns_unicode_filter.py: Checking "+qstate.qinfo.qname_str)

        if (qstate.qinfo.qname_str.startswith(unicodefilter, 0, 4)):
            log_info("dns_unicode_filter.py: "+qstate.qinfo.qname_str+" blacklisted")
            
            msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
            if (qstate.qinfo.qtype == RR_TYPE_A) or (qstate.qinfo.qtype == RR_TYPE_ANY):
                msg.answer.append("%s 10 IN A %s" % (qstate.qinfo.qname_str, intercept_address))


            if not msg.set_return_msg(qstate):
                qstate.ext_state[id] = MODULE_ERROR 
                return True

            qstate.return_msg.rep.security = 2

            qstate.return_rcode = RCODE_NOERROR
            qstate.ext_state[id] = MODULE_FINISHED 
            return True
        else:
            qstate.ext_state[id] = MODULE_WAIT_MODULE 
            return True

    if event == MODULE_EVENT_MODDONE:
#        log_info("pythonmod: iterator module done")
        qstate.ext_state[id] = MODULE_FINISHED 
        return True
      
    log_err("pythonmod: bad event")
    qstate.ext_state[id] = MODULE_ERROR
    return True

