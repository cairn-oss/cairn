resource "vsphere_virtual_machine" "app" {
  name = "app-vm"
  # VS001: no reservations/limits · VS003: no annotation
  disk {
    label            = "disk0"
    thin_provisioned = false # VS002
  }
}
