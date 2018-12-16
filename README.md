# gomozzie
This is a plugin for the [Mosquitto](https://github.com/eclipse/mosquitto) MQTT server to authenticate and authorise users from [ForgeRock Access Management](https://www.forgerock.com/platform/access-management). 
This is a pure GO implementation but was inspired by the C Mosquitto plugin [mosquitto-auth-plug](https://github.com/bjornwennberg71/mosquitto-auth-plug).

## Configuration

The plugin is configured via a Mosquitto server's own configuration file. Use the `auth_plugin` option to load the gomozzie plugin e.g.

```
auth_plugin /path/to/gomozzie.so
```

Options `auth_opt_` are automatically handed to the plugin. The following options are used:

| Option            |  Mandatory  |
| ---------------------| :---------: |
|  |            
| openam_host           |      Y      | 
| openam_port           |      Y      | 
| openam_path           |      Y      |         
| openam_realm          |      Y      |           
| openam_cookiename     |      Y      |         
| openam_client_id      |      Y      |       
| openam_client_secret  |      Y      | 
| openam_application    |      Y      |
| openam_agent_realm    |      Y      |
| openam_agent_user     |      Y      |
| openam_agent_password |      Y      |
| openam_use_tls .      | .    N .    |
| openam_log_dest .     | .    N .    |

## Disclaimer
This is a personal science project and is not an official ForgeRock product.
