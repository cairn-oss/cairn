resource "vsphere_virtual_machine" "app" {
  name               = "app-vm"
  memory_reservation = 2048
  cpu_limit          = 2000
  annotation         = "owner=platform; env=prod; purpose=app tier"
  disk {
    label            = "disk0"
    thin_provisioned = true
  }
}
