# KillSwitch
A qt core application which creates firewall rules using WMI COM API to block outgoing traffic. Uses simple QWebEngine-based UI.

# How it works
The responsibility to monitor traffic lies on the firewall, so it would be natural to manipulate firewall through WMI COM API or CLI commands to create a rule. App creates 1 rule to block all outgoing traffic. Multiple clients can connect to the app through web UI and see the status of blocking and enable or disable the killswitch. The protocol of App-UI interaction is string based.

# Things that still can be implemented or improved
1. Monitoring the actual state of a rule object with wmi events.
2. Internal state object can be removed, and the actual status of a rule instance will be queried directly from wmi with every user request.
3. Ability to block specific IP addresses.
