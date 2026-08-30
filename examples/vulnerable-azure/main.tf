# Intentionally vulnerable Azure stack — triggers Checkov Azure checks.
# Never deploy as-is; used to verify tf-eu-guard Azure registry mappings.


resource "azurerm_resource_group" "example" {
  name     = "vulnerable-rg"
  location = "West Europe"
}

resource "azurerm_storage_account" "data" {
  name                     = "vualexampledata01"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_account_network_rules" "data" {
  storage_account_id = azurerm_storage_account.data.id
  default_action     = "Allow"
}

resource "azurerm_postgresql_server" "db" {
  name                = "vuln-pgdb"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  administrator_login = "adminuser"
  sku_name            = "GP_Gen5_2"
  version             = "11"
  ssl_mode            = "Disabled"
}

resource "azurerm_postgresql_firewall_rule" "open" {
  name                = "allow-all"
  resource_group_name = azurerm_resource_group.example.name
  server_name         = azurerm_postgresql_server.db.name
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "255.255.255.255"
}

resource "azurerm_linux_web_app" "app" {
  name                = "vuln-app"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id
  https_only          = false
}

resource "azurerm_service_plan" "example" {
  name                = "vuln-plan"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  os_type             = "Linux"
  sku_name            = "S1"
}

resource "azurerm_key_vault" "secrets" {
  name                = "vuln-kv-12345"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  tenant_id           = "00000000-0000-0000-0000-000000000000"
}
