# create restricted upload user
sudo useradd -m -d /home/auditupload

# prepare ssh directory
sudo mkdir -p /home/auditupload/.ssh
sudo touch /home/auditupload/.ssh/authorized_keys
sudo chmod 700 /home/auditupload/.ssh
sudo chmod 600 /home/auditupload/.ssh/authorized_keys
sudo chown -R auditupload:auditupload /home/auditupload/.ssh

# create directory where logs arrive
sudo mkdir -p /opt/homelab-audit/reports
sudo chown auditupload:auditupload /opt/homelab-audit/reports
sudo chmod 750 /opt/homelab-audit/reports
