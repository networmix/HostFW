# HostFW
This is a simple host firewall for Linux. It consists of the following three parts:
* XDP program that hooks on the ingress interfaces of the host and implements the firewall rules.
* Firewall userspace service that communicates with the XDP program and allows the user to add/remove firewall rules via a REST API.
* CLI tool that allows the user to start/stop the firewall service.