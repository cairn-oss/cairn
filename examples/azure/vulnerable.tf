resource "azurerm_network_security_rule" "ssh" {
  name                        = "allow-ssh"
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  destination_port_range      = "22"
  source_address_prefix       = "*" # AZ001 CRITICAL
  destination_address_prefix  = "*"
}

resource "azurerm_storage_account" "data" {
  name                            = "acmedata"
  allow_nested_items_to_be_public = true # AZ002
  # AZ006: no tags
}

resource "azurerm_mssql_server" "db" {
  name                          = "acme-sql"
  public_network_access_enabled = true # AZ003
}

resource "azurerm_managed_disk" "data" {
  name = "data-disk" # AZ004: no encryption set
}

resource "azurerm_linux_virtual_machine" "batch" {
  name = "batch"
  size = "Standard_D16s_v5" # AZ005 (~$560/mo)
}
