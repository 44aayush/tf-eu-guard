provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "us" {
  name     = "rg-us"
  location = "eastus"
}
