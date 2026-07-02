# SURU — Networking module
# terraform-docs: module for VLAN / bridge network definitions

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 4.5"
    }
  }
}

variable "subnet" {
  description = "CIDR block for the internal SIEM network"
  type        = string
  default     = "172.28.0.0/24"
}

variable "env" {
  description = "Environment name"
  type        = string
}

variable "tier" {
  description = "SURU tier level this network belongs to (siem_internal is tier3)"
  type        = string
  default     = "tier3"
  validation {
    condition     = contains(["tier1", "tier2", "tier3", "tier4"], var.tier)
    error_message = "tier must be one of tier1, tier2, tier3, tier4."
  }
}

resource "docker_network" "siem_internal" {
  name   = "suru-siem-internal-${var.env}"
  driver = "bridge"
  ipam_config {
    subnet = var.subnet
  }
  labels {
    label = "project"
    value = "suru"
  }
  labels {
    label = "component"
    value = "networking"
  }
  labels {
    label = "env"
    value = var.env
  }
  labels {
    label = "managed_by"
    value = "terraform"
  }
  labels {
    label = "tier"
    value = var.tier
  }
}

output "network_id" {
  description = "ID of the created SIEM internal network"
  value       = docker_network.siem_internal.id
}
