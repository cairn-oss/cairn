resource "google_compute_firewall" "ssh" {
  name          = "allow-ssh"
  network       = "default"
  source_ranges = ["0.0.0.0/0"] # GCP001 CRITICAL
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_storage_bucket" "data" {
  name = "acme-data" # GCP002 + GCP006
}

resource "google_sql_database_instance" "db" {
  name = "acme-db"
  settings {
    ip_configuration {
      ipv4_enabled = true # GCP003
    }
  }
}

resource "google_compute_instance" "batch" {
  name         = "batch"
  machine_type = "n2-standard-16" # GCP005 (~$560/mo), GCP004 no shielded
}
