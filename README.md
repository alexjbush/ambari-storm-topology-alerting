# ambari-storm-topology-alerting

Ambari Alerts triggered from Storm UI API topology attributes.

Works in both Kerberised and non-Kerberised environments.

## Alert definition

You can alert off any of the topology attributes found here: [STORM-UI-REST-API.md](https://github.com/Parth-Brahmbhatt/incubator-storm/blob/master/STORM-UI-REST-API.md#apiv1topologyid-get)

You can choose any of these fields, and use any of the following operators to match alert thresholds: (lt,gt,le,ge,eq,ne). The Critical threshold takes preference in the matching.

You can specify either the topology name or id to reference a given topology.

The TYPE field must match the one from the API.

In the case of times-sliced windows, the minimum window of 600s will be chosen.

##### Optional HTTPS
You can optionally allow the alert to access the Storm UI via HTTPS by providing two additional variables in the alert definition.
```javascript
{
  "name": "https_enabled",
  "display_name": "Use https for Storm UI",
  "value": "true",
  "type": "STRING",
  "description": "Set to true to use HTTPS to access the Storm UI"
},
{
  "name": "https_port",
  "display_name": "Port to access HTTPS Storm UI",
  "value": "8740",
  "type": "STRING",
  "description": "The port on which Storm UI servers HTTPS"
}
```

### Examples

There are two example API alert definitions.

#### Topology Status

This will alert to Critical if a topology is not in an active state.

[topology_state.json](topology_state.json)

#### Maximum Latency

This will alert is the maximum latency (average time taken for a message to traverse a topology) breaches certain thresholds.

[maximum_latency.json](maximum_latency.json)

## Alert installation

> Taken from [https://github.com/monolive/ambari-custom-alerts](https://github.com/monolive/ambari-custom-alerts)

Push the new alert via Ambari REST API.

```sh
curl -u admin:admin -i -H 'X-Requested-By: ambari' -X POST -d @alerts.json http://ambari.cloudapp.net:8080/api/v1/clusters/hdptest/alert_definitions
```
You will also need to copy the python script in /var/lib/ambari-server/resources/host_scripts and restart the ambari-server. After restart the script will be pushed in /var/lib/ambari-agent/cache/host_scripts on the different hosts.

You can find the ID of your alerts by running
```sh
curl -u admin:admin -i -H 'X-Requested-By: ambari' -X GET http://ambari.cloudapp.net:8080/api/v1/clusters/hdptest/alert_definitions
```

If we assume, that your alert is id 103. You can force the alert to run by
```sh
curl -u admin:admin -i -H 'X-Requested-By: ambari' -X PUT  http://ambari.cloudapp.net:8080/api/v1/clusters/hdptest/alert_definitions/103?run_now=true
```

## [License](LICENSE)

Copyright (c) 2016 Alex Bush.
Licensed under the [Apache License](LICENSE).
