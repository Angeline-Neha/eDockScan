#!/usr/bin/env python3
"""
Auto-generated script to rescan 85 images with missing data
Generated from rescan_missing.py
"""

import sys
import os

# Import your scanner
from extract_model import extract_dataset_parallel

# Images to rescan
SAFE_IMAGES = ['nginx:alpine', 'nginx:1.25-alpine', 'nginx:1.24-alpine', 'python:3.10-slim', 'python:3.11-slim', 'influxdb:alpine', 'rabbitmq:3-alpine', 'kibana:8.11.0', 'grafana/grafana:latest', 'jenkins/jenkins:lts-alpine', 'openjdk:17-alpine', 'perl:slim', 'rust:1.75-alpine', 'tomcat:10-jdk17-temurin-jammy', 'wordpress:latest', 'ghost:alpine', 'drupal:latest', 'python:3.9-slim', 'python:3.12-slim', 'node:20-alpine', 'node:16-alpine', 'node:18-alpine', 'postgres:15-alpine', 'node:21-alpine', 'postgres:16-alpine', 'redis:7-alpine', 'postgres:14-alpine', 'alpine:latest', 'alpine:3.19', 'redis:6-alpine', 'alpine:3.18', 'golang:1.21-alpine', 'golang:1.20-alpine', 'debian:bookworm-slim', 'mysql:8.0', 'mysql:8.2', 'debian:bullseye-slim', 'ubuntu:23.10', 'ubuntu:22.04', 'haproxy:2.9-alpine', 'mariadb:11', 'ruby:3.1-alpine', 'ruby:3.2-alpine', 'memcached:1.6-alpine', 'httpd:alpine', 'busybox:latest', 'traefik:latest']

RISKY_IMAGES = ['ubuntu:14.04', 'ubuntu:16.04', 'ubuntu:18.04', 'ubuntu:12.04', 'redis:3.2', 'redis:3.0', 'redis:4.0', 'nginx:1.10', 'nginx:1.12', 'httpd:2.2', 'ruby:2.1', 'ruby:2.3', 'golang:1.12', 'webgoat/goatandwolf', 'debian:jessie', 'debian:wheezy', 'debian:stretch', 'centos:7', 'centos:6', 'centos:5', 'python:2.7', 'python:3.4', 'python:3.6', 'python:2.7-slim', 'python:3.5', 'node:10', 'node:8', 'node:4', 'node:6', 'node:11', 'node:12', 'php:5.6', 'php:5.5', 'php:7.1', 'postgres:9.3', 'postgres:9.2', 'mysql:5.5', 'mysql:5.7']

if __name__ == "__main__":
    print("="*70)
    print(f"🔄 Rescanning {len(SAFE_IMAGES) + len(RISKY_IMAGES)} images")
    print("="*70)
    print(f"Safe images: {len(SAFE_IMAGES)}")
    print(f"Risky images: {len(RISKY_IMAGES)}")
    print("="*70)
    
    # Run the scan
    df = extract_dataset_parallel(
        safe_images=SAFE_IMAGES,
        risky_images=RISKY_IMAGES,
        output_csv='data/rescanned_images.csv',
        timeout_per_image=300,
        max_workers=3
    )
    
    print("\n✅ Rescan complete!")
    print("📊 Results saved to: data/rescanned_images.csv")
    print("\n📋 Next steps:")
    print("   1. Review the rescanned data")
    print("   2. Run: python rescan_missing.py merge")
    print("      to merge back into data/final_training_data.csv")
