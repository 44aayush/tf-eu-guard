provider "google" {
  region = "us-central1"
}

resource "google_storage_bucket" "us" {
  name     = "pii-bucket"
  location = "US"
}
