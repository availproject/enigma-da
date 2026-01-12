#!/bin/bash

# Local Development Helper Script
# Quick commands for local development with docker-compose.local.yml

set -e

COMPOSE_FILE="docker-compose.local.yml"

show_help() {
    cat << EOF
Usage: ./local-dev.sh [COMMAND]

Local development helper for enigma-da service

Commands:
    setup       Create certs directory and check prerequisites
    build       Build the local debug Docker image
    up          Start the service (foreground)
    start       Start the service (background/detached)
    stop        Stop the service
    restart     Restart the service
    logs        Show and follow logs
    clean       Stop service and remove containers, networks, volumes
    rebuild     Clean, build, and start the service
    help        Show this help message

Examples:
    ./local-dev.sh setup       # First time setup
    ./local-dev.sh build       # Build the image
    ./local-dev.sh up          # Start and watch logs
    ./local-dev.sh start       # Start in background
    ./local-dev.sh logs        # View logs

Prerequisites:
    - Docker and Docker Compose installed
    - Certificate files in ./certs/ directory:
      * ca.crt
      * server.crt
      * server.key

    Generate test certificates:
      ./scripts/certificates_local.sh
      mkdir -p certs
      mv ca.crt server.crt server.key certs/

EOF
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        echo "Error: Docker is not installed"
        exit 1
    fi

    if ! docker compose version &> /dev/null && ! command -v docker-compose &> /dev/null; then
        echo "Error: Docker Compose is not installed"
        exit 1
    fi
}

setup() {
    echo "Setting up local development environment..."
    
    check_docker
    
    # Create directories
    echo "Creating directories..."
    mkdir -p certs
    mkdir -p data
    
    # Check for certificate files
    if [ ! -f "certs/ca.crt" ] || [ ! -f "certs/server.crt" ] || [ ! -f "certs/server.key" ]; then
        echo ""
        echo "⚠️  Certificate files not found in ./certs/"
        echo ""
        echo "To generate test certificates, run:"
        echo "  ./scripts/certificates_local.sh"
        echo "  mv ca.crt server.crt server.key certs/"
        echo ""
        exit 1
    fi
    
    echo "✅ Setup complete!"
    echo ""
    echo "Next steps:"
    echo "  ./local-dev.sh build    # Build the Docker image"
    echo "  ./local-dev.sh up       # Start the service"
}

build() {
    echo "Building local debug image..."
    check_docker
    docker compose -f "$COMPOSE_FILE" build
    echo "✅ Build complete!"
}

up() {
    echo "Starting service (foreground)..."
    check_docker
    docker compose -f "$COMPOSE_FILE" up
}

start() {
    echo "Starting service (background)..."
    check_docker
    docker compose -f "$COMPOSE_FILE" up -d
    echo "✅ Service started!"
    echo ""
    echo "View logs: ./local-dev.sh logs"
}

stop() {
    echo "Stopping service..."
    check_docker
    docker compose -f "$COMPOSE_FILE" down
    echo "✅ Service stopped!"
}

restart() {
    echo "Restarting service..."
    stop
    start
}

logs() {
    check_docker
    docker compose -f "$COMPOSE_FILE" logs -f
}

clean() {
    echo "Cleaning up (removing containers, networks, volumes)..."
    check_docker
    docker compose -f "$COMPOSE_FILE" down -v
    echo "✅ Cleanup complete!"
}

rebuild() {
    echo "Rebuilding service (clean + build + start)..."
    clean
    build
    start
}

# Main script logic
case "${1:-help}" in
    setup)
        setup
        ;;
    build)
        build
        ;;
    up)
        up
        ;;
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    logs)
        logs
        ;;
    clean)
        clean
        ;;
    rebuild)
        rebuild
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Error: Unknown command '$1'"
        echo ""
        show_help
        exit 1
        ;;
esac
