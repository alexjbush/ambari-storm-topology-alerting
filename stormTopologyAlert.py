#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
# Alert on the storm topology rest api
#
# Alex Bush <abush@hortonworks.com>
#

import time
import urllib2
import ambari_simplejson as json # simplejson is much faster comparing to Python 2.6 json module and has the same functions set.
import logging
import traceback

from resource_management.libraries.functions.curl_krb_request import curl_krb_request
from resource_management.core.environment import Environment

ALLOWED_COMPARISON_VALUES=dict()
ALLOWED_COMPARISON_VALUES['STRING']=['eq','ne']
ALLOWED_COMPARISON_VALUES['LONG']=['eq','ne','gt','lt','ge','le']
ALLOWED_COMPARISON_VALUES['INTEGER']=['eq','ne','gt','lt','ge','le']
ALLOWED_COMPARISON_VALUES['DOUBLE']=['eq','ne','gt','lt','ge','le']

CRITICAL_KEY = 'critical.threshold'
WARNING_KEY = 'warning.threshold'
COMPARISON_KEY = 'comparison'
FIELD_TYPE_KEY = 'field_type'
FIELD_NAME_KEY = 'field_name'
TOPOLOGY_ID_KEY = 'topology_id'
HTTPS_ENABLED_KEY = 'https_enabled'
HTTPS_PORT_KEY = 'https_port'

DEFAULT_WINDOW_VALUE = '600'

STORM_UI_PORT = '{{storm-site/ui.port}}'

CONNECTION_TIMEOUT_KEY = 'connection.timeout'
CONNECTION_TIMEOUT_DEFAULT = 5.0

KERBEROS_KEYTAB = '{{cluster-env/smokeuser_keytab}}'
KERBEROS_PRINCIPAL = '{{cluster-env/smokeuser_principal_name}}'
SECURITY_ENABLED_KEY = '{{cluster-env/security_enabled}}'
SMOKEUSER_KEY = "{{cluster-env/smokeuser}}"
EXECUTABLE_SEARCH_PATHS = '{{kerberos-env/executable_search_paths}}'

logger = logging.getLogger('ambari_alerts')

def get_tokens():
  """
  Returns a tuple of tokens in the format {{site/property}} that will be used
  to build the dictionary passed into execute
  """
  return (STORM_UI_PORT, EXECUTABLE_SEARCH_PATHS, KERBEROS_KEYTAB, KERBEROS_PRINCIPAL, SECURITY_ENABLED_KEY, SMOKEUSER_KEY)

def execute(configurations={}, parameters={}, host_name=None):
  """
  Returns a tuple containing the result code and a pre-formatted result label
  Keyword arguments:
  configurations (dictionary): a mapping of configuration key to value
  parameters (dictionary): a mapping of script parameter key to value
  host_name (string): the name of this host where the alert is running
  """

  if configurations is None:
    return (('UNKNOWN', ['There were no configurations supplied to the script.']))

  # Set configuration settings

  if STORM_UI_PORT in configurations:
    stormuiport = configurations[STORM_UI_PORT]

  if SMOKEUSER_KEY in configurations:
    smokeuser = configurations[SMOKEUSER_KEY]

  executable_paths = None
  if EXECUTABLE_SEARCH_PATHS in configurations:
    executable_paths = configurations[EXECUTABLE_SEARCH_PATHS]

  security_enabled = False
  if SECURITY_ENABLED_KEY in configurations:
    security_enabled = str(configurations[SECURITY_ENABLED_KEY]).upper() == 'TRUE'

  kerberos_keytab = None
  if KERBEROS_KEYTAB in configurations:
    kerberos_keytab = configurations[KERBEROS_KEYTAB]

  kerberos_principal = None
  if KERBEROS_PRINCIPAL in configurations:
    kerberos_principal = configurations[KERBEROS_PRINCIPAL]
    kerberos_principal = kerberos_principal.replace('_HOST', host_name)

  # parse script arguments
  connection_timeout = CONNECTION_TIMEOUT_DEFAULT
  if CONNECTION_TIMEOUT_KEY in parameters:
    connection_timeout = float(parameters[CONNECTION_TIMEOUT_KEY])

  if WARNING_KEY in parameters:
    warning_val = parameters[WARNING_KEY]

  if CRITICAL_KEY in parameters:
    critical_val = parameters[CRITICAL_KEY]

  if COMPARISON_KEY in parameters:
    comparison_val = parameters[COMPARISON_KEY]

  if FIELD_TYPE_KEY in parameters:
    field_type_val = parameters[FIELD_TYPE_KEY]

  if FIELD_NAME_KEY in parameters:
    field_name_val = parameters[FIELD_NAME_KEY]

  if TOPOLOGY_ID_KEY in parameters:
    topology_id_val = parameters[TOPOLOGY_ID_KEY]

  if HTTPS_ENABLED_KEY in parameters and lower(str(parameters[HTTPS_ENABLED_KEY])) == 'true':
    if HTTPS_PORT_KEY in parameters:
      stormuiport = str(parameters[HTTPS_PORT_KEY])
      protocol = 'https'
    else:
      return (('UNKNOWN', ['Please provide a port number as parameter: '+HTTPS_PORT_KEY]))
  else:
    protocol = 'http'

  # Check comparison and field type combination
  if not field_type_val in ALLOWED_COMPARISON_VALUES.keys():
    return (('UNKNOWN', ['Field type error, must be one of: '+','.join(ALLOWED_COMPARISON_VALUES.keys())]))

  if not comparison_val in ALLOWED_COMPARISON_VALUES[field_type_val]:
    return (('UNKNOWN', ['Comparison error, must be one of: '+','.join(ALLOWED_COMPARISON_VALUES[field_type_val])+' for given field type: '+field_type_val+'. Type not valid: '+comparison_val]))

  label = None
  result_code = "OK"

  try:

    # Set up url to query
    rest_api_request_summary = protocol+'://'+host_name+':'+stormuiport+'/api/v1/topology/summary'

    # Kerberos curl
    if kerberos_principal is not None and kerberos_keytab is not None and security_enabled:

      # curl requires an integer timeout
      curl_connection_timeout = int(connection_timeout)
      summary_response, error_msg, time_millis = curl_krb_request('/tmp/', kerberos_keytab, kerberos_principal, rest_api_request_summary, "storm_topology", executable_paths, False, "Storm Topology Rest API", smokeuser, connection_timeout=curl_connection_timeout)

    # Non-kerberos curl
    else:
      req = urllib2.Request(rest_api_request_summary)
      response = urllib2.urlopen(req)
      summary_response = response.read()

    # Get summary to check if the topology is in there
    summary = json.loads(summary_response)
    topology_name = None
    topology_id = None
    for top in summary['topologies']:
      if topology_id_val == top['id']:
        topology_id = top['id']
      elif topology_id_val == top['name']:
        if topology_name or topology_id:
          return (('UNKNOWN', ['Multiple topologies for with id or name: '+topology_id_val]))
        topology_id = top['id']

    if not topology_id:
      return (('UNKNOWN', ['No topology found with id or name: '+topology_id_val]))

    # Get topology information
    rest_api_request_topology = protocol+'://'+host_name+':'+stormuiport+'/api/v1/topology/'+topology_id

    # Kerberos curl
    if kerberos_principal is not None and kerberos_keytab is not None and security_enabled:
      topology_response, error_msg, time_millis = curl_krb_request('/tmp/', kerberos_keytab, kerberos_principal, rest_api_request_topology, "storm_topology", executable_paths, False, "Storm Topology Rest API", smokeuser, connection_timeout=curl_connection_timeout)

    # Non-kerberos curl
    else:
      req = urllib2.Request(rest_api_request_topology)
      response = urllib2.urlopen(req)
      topology_response = response.read()

    # Load response
    json_response = json.loads(topology_response)
    field_val = json_response

    # Retrive value
    for field in field_name_val.split('.'):
      if not field in field_val.keys():
        return (('UNKNOWN', ['Could not find field: '+field_name_val+' in response: '+topology_response]))
      else:
        field_val = field_val[field]
        if isinstance(field_val, list):
          for elem in field_val:
            if 'window' in elem.keys() and elem['window'] == DEFAULT_WINDOW_VALUE:
              field_val = elem
              break

    #Cast all three values to appropriate type
    raw_field_values = { 'field':field_val, 'WARNING':warning_val, 'CRITICAL':critical_val }
    field_values = dict()
    for field in raw_field_values.keys():
      success,value = try_cast(raw_field_values[field],field_type_val)
      if success:
        field_values[field] = value
      else:
        return (('UNKNOWN', [field+' error: '+value]))

    #Assume correct
    label = 'The current value is {c}. Warning threshold is {o} {w} and critical threshold is {o} {t}.'.format(c=field_values['field'],o=comparison_val,w=field_values['WARNING'],t=field_values['CRITICAL'])

    #Perform comparison for each type
    for level in ['WARNING', 'CRITICAL']:
      if comparison(field_values['field'],field_values[level],comparison_val):
        result_code = level
        label = 'The current value is {c}, the threshold is {o} {t}'.format(c=field_values['field'],o=comparison_val,t=field_values[level])

  #Catch any exceptions during the curls
  except:
    label = traceback.format_exc()
    result_code = 'UNKNOWN'

  return ((result_code, [label]))


#
# Some utility functions
#

# Cast a value returned by API to given type
def try_cast(value,to_type):
  try:
    if to_type == 'STRING':
      ret_value = str(value)
    elif to_type == 'INTEGER':
      ret_value = int(value)
    elif to_type == 'LONG':
      ret_value = int(value)
    elif to_type == 'DOUBLE':
      ret_value = float(value)
  except:
    return (False,'Error casting '+value+' to type '+to_type)
  return (True,ret_value)

# Perform comparison on two values
def comparison(val1,val2,comp):
  if comp == 'eq' and val1 == val2:
    return True
  elif comp == 'ne' and val1 != val2:
    return True
  elif comp == 'ge' and val1 >= val2:
    return True
  elif comp == 'gt' and val1 > val2:
    return True
  elif comp == 'le' and val1 <= val2:
    return True
  elif comp == 'lt' and val1 < val2:
    return True
  return False
