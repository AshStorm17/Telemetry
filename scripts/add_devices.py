from models import db
from models.device import Device

def add_sample_devices():
    if Device.query.count() == 0:
        sample_devices = [
            Device(name="Core Router", ip_address="192.168.1.1", 
                  device_type="router", location="Data Center"),
            Device(name="Edge Switch 1", ip_address="192.168.1.2", 
                  device_type="switch", location="Main Office"),
            Device(name="Firewall", ip_address="192.168.1.3", 
                  device_type="firewall", location="Data Center"),
            Device(name="Distribution Switch", ip_address="192.168.1.4", 
                  device_type="switch", location="Branch Office"),
            Device(name="Access Point", ip_address="192.168.1.5", 
                  device_type="access_point", location="Conference Room"),
        ]
        for device in sample_devices:
            db.session.add(device)
        db.session.commit()

if __name__ == '__main__':
    add_sample_devices()