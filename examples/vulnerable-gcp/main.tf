# Intentionally vulnerable GCP stack — triggers Checkov GCP checks.
# Never deploy as-is; used to verify tf-eu-guard GCP registry mappings.


resource "google_storage_bucket" "data" {
  name          = "vuln-example-data-bucket"
  location      = "EU"
  force_destroy = false
}

resource "google_storage_bucket_iam_binding" "public" {
  bucket = google_storage_bucket.data.name
  role   = "roles/storage.objectViewer"
  members = [
    "allUsers",
  ]
}

resource "google_sql_database_instance" "db" {
  name             = "vuln-db"
  database_version = "POSTGRES_13"
  region           = "europe-west1"

  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
      require_ssl  = false
    }
    backup_configuration {
      enabled = false
    }
  }
}

resource "google_compute_subnetwork" "default" {
  name          = "vuln-subnet"
  ip_cidr_range = "10.0.0.0/16"
  region        = "europe-west1"
  network       = google_compute_network.default.id
  # log_config intentionally omitted
}

resource "google_compute_network" "default" {
  name = "vuln-network"
}

resource "google_container_cluster" "gke" {
  name               = "vuln-gke"
  location           = "europe-west1"
  initial_node_count = 2
  enable_legacy_abac = true
  remove_default_node_pool = false

  master_auth {
    username = "admin"
    password = "not-a-real-password"
  }
}

resource "google_container_node_pool" "pool" {
  name       = "vuln-pool"
  cluster    = google_container_cluster.gke.name
  location   = "europe-west1"
  node_count = 2

  management {
    auto_repair  = false
    auto_upgrade = false
  }

  node_config {
    machine_type = "e2-medium"
    image_type   = "UBUNTU"
  }
}

resource "google_compute_instance" "vm" {
  name         = "vuln-vm"
  machine_type = "e2-small"
  zone         = "europe-west1-b"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = google_compute_network.default.id
    access_config { }
  }

  metadata = {
    serial-port-enable = "true"
  }
}

resource "google_dns_managed_zone" "zone" {
  name     = "vuln-zone"
  dns_name = "vuln.example.com."
}
