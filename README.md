
# Kubernetes Security Checklist
Below is a basic Kubernetes security checklist. This list is not exhaustive, and certain items may only be applicable depending on your cluster configuration.

Cluster security can mainly be categorized into three areas: authentication security, pod security, and network security.

![4c-cloud](./img/cloud-native.png)


# Kubernetes Security Checklist

# Authentication & Authorization

    system:masters group is not used for user or component authentication after bootstrapping
    The kube-controller-manager is running with --use-service-account-credentials enabled
    The root certificate is protected (either an offline CA, or a managed online CA with effective access controls)
    Intermediate and leaf certificates have an expiry date no more than 3 years in the future
    A process exists for periodic access review, and reviews occur no more than 24 months apart
    Develop a role-based access model for each cluster
    Configure RBAC for the Kubernetes cluster with rights assigned based on least privilege and separation of duties
    Each service should have a unique service account with RBAC rights
    Developer access to production requires security team approval
    User impersonation and anonymous authentication (except for /healthz, /readyz, /livez) are prohibited
    Cluster interaction should be through privileged access management systems
    Information systems should be in separate namespaces, ideally managed by different teams
    Regularly audit RBAC rights
    Enforce Two-factor authentication (2FA)
    Ensure Compliance with Relevant Industry Standards
    Protect your applications against breaches
    Protect against Denial Of Service (DoS)
    Have a public security policy
    Have a public bug bounty program
    Use an IdP server for Kubernetes API user authentication, avoid service account tokens
    Centralized certificate management is advised for cluster certificates
    Personalize user accounts and name service accounts based on their purpose and access rights

# Infrastructure

    Automatically configure & update your servers
    Backup regularly
    Check your SSL / TLS configurations
    Control access on your cloud providers
    Encrypt all the things
    Harden SSH configurations
    Use Kubernetes network policies to restrict access
    Use RBAC to restrict access
    Use PodSecurityPolicies to restrict what can run on your cluster
    Use Service Mesh to restrict access to your cluster
    Use network segmentation to isolate your cluster from the Internet
    Use Secrets Management to securely store and manage secrets
    Monitor for anomalies and security threats
    Log all the things
    Manage secrets with dedicated tools and vaults
    Upgrade your servers regularly
    Use an immutable infrastructure

# Network Security

    CNI plugins in-use supports network policies
    Ingress and egress network policies are applied to all workloads in the cluster
    Default network policies within each namespace, selecting all pods, denying everything, are in place
    If appropriate, a service mesh is used to encrypt all communications inside of the cluster
    The Kubernetes API, kubelet API and etcd are not exposed publicly on Internet
    Access from the workloads to the cloud metadata API is filtered
    Use of LoadBalancer and ExternalIPs is restricted
    Separate internet-interacting nodes (DMZ) from internal service-interacting nodes

# Pod Security

    RBAC rights to create, update, patch, delete workloads is only granted if necessary
    Appropriate Pod Security Standards policy is applied for all namespaces and enforced
    Memory limit is set for the workloads with a limit equal or inferior to the request
    CPU limit might be set on sensitive workloads
    For nodes that support it, Seccomp is enabled with appropriate syscalls profile for programs
    For nodes that support it, AppArmor or SELinux is enabled with appropriate profile for programs
    Pod placement is done in accordance with the tiers of sensitivity of the application
    Sensitive applications are running isolated on nodes or with specific sandboxed runtimes
    Avoid running pods under root account, use runAsUser parameter
    Set allowPrivilegeEscalation to false and avoid privileged pods
    Use readonlyRootFilesystem, avoid hostPID, hostIPC, hostNetwork, unsafe system calls, and hostPath
    Set minimum CPU/RAM limits and capabilities based on least privileges
    Use non-default namespace and apply seccomp, apparmor or selinux profiles

# Logs, Auditing, and Monitoring

    Audit logs, if enabled, are protected from general access
    The /logs API is disabled (you are running kube-apiserver with --enable-logs-handler=false)
    Check that TLS certificates are not set to expire
    Detect insider threats
    Get notified when your app is under attack
    Monitor third party vendors
    Monitor your authorizations
    Monitor your DNS expiration date

# Secrets

    ConfigMaps are not used to hold confidential data
    Encryption at rest is configured for the Secret API
    If appropriate, a mechanism to inject secrets stored in third-party storage is deployed and available
    Service account tokens are not mounted in pods that don't require them
    Bound service account token volume is in-use instead of non-expiring tokens

# Images

    Minimize unnecessary content in container images
    Container images are configured to be run as unprivileged user
    References to container images are made by sha256 digests (rather than tags) or the provenance of the image is validated by verifying the image's digital signature at deploy time via admission control
    Container images are regularly scanned during creation and in deployment, and known vulnerable software is patched
    Avoid RUN with sudo, use COPY instead of ADD
    Explicitly indicate package versions and avoid storing sensitive information in Dockerfile
    Minimize package composition, forwarded port range, and number of layers in the image
    Avoid installing wget, curl, netcat in production images
    Use .dockerignore, absolute path for WORKDIR, and beware of recursive copying
    Avoid using the latest tag and running remote control tools in a container
    Check package integrity during build process and generate image signature after scanning
    Regularly check Dockerfile during development and images during application lifecycle by automated scanners
    Build secure CI/CD as same as supply chain process

# Admission controllers

    An appropriate selection of admission controllers is enabled
    A pod security policy is enforced by the Pod Security Admission or/and a webhook admission controller
    The admission chain plugins and webhooks are securely configured

# Code

    Integrate security scanners in your CI pipeline
    Keep your dependencies up to date
    Protect CI/CD tools like your product
    Run Security tests on code changes

# Operational

    Determine who is K8S cluster admin
    Establish onboarding process
    User documentation (Onboarding, Operating, Container image pipeline, Finding images to use)
    Gamify security and train employees on a regular basis

I hope you found this article insightful! I'd love to hear your thoughts and feedback. 😎
