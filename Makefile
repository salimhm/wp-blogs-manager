# Makefile for WordPress AI Publisher

.PHONY: help build up down restart logs shell migrate makemigrations createsuperuser test clean backup

help:
	@echo "WordPress AI Publisher - Docker Commands"
	@echo ""
	@echo "Setup Commands:"
	@echo "  make setup          - Initial setup (copy .env, build, migrate)"
	@echo "  make build          - Build Docker images"
	@echo "  make up             - Start all services"
	@echo "  make down           - Stop all services"
	@echo ""
	@echo "Development Commands:"
	@echo "  make restart        - Restart all services"
	@echo "  make logs           - View logs (all services)"
	@echo "  make logs-web       - View web service logs"
	@echo "  make logs-db        - View database logs"
	@echo "  make shell          - Access Django shell"
	@echo "  make bash           - Access web container bash"
	@echo ""
	@echo "Database Commands:"
	@echo "  make migrate        - Run database migrations"
	@echo "  make makemigrations - Create new migrations"
	@echo "  make createsuperuser - Create Django superuser"
	@echo "  make dbshell        - Access PostgreSQL shell"
	@echo "  make backup         - Backup database"
	@echo ""
	@echo "Maintenance Commands:"
	@echo "  make test           - Run tests"
	@echo "  make collectstatic  - Collect static files"
	@echo "  make clean          - Remove containers and volumes"
	@echo "  make rebuild        - Clean rebuild"

setup:
	@echo "Setting up WordPress AI Publisher..."
	@if [ ! -f .env ]; then cp .env.example .env; echo "Created .env file - please edit with your API keys"; fi
	docker-compose build
	docker-compose up -d
	@echo "Waiting for database to be ready..."
	@sleep 5
	docker-compose exec web python manage.py migrate
	docker-compose exec web python manage.py collectstatic --noinput
	@echo "Setup complete! Access the app at http://localhost"

build:
	docker-compose build

up:
	docker-compose up -d
	@echo "Services started. Access at http://localhost"

down:
	docker-compose down

restart:
	docker-compose restart

logs:
	docker-compose logs -f

logs-web:
	docker-compose logs -f web

logs-db:
	docker-compose logs -f db

shell:
	docker-compose exec web python manage.py shell

bash:
	docker-compose exec web bash

migrate:
	docker-compose exec web python manage.py migrate

makemigrations:
	docker-compose exec web python manage.py makemigrations

createsuperuser:
	docker-compose exec web python manage.py createsuperuser

dbshell:
	docker-compose exec db psql -U dbuser -d wordpress_ai_publisher

collectstatic:
	docker-compose exec web python manage.py collectstatic --noinput

test:
	docker-compose exec web python manage.py test

backup:
	@mkdir -p backups
	docker-compose exec db pg_dump -U dbuser wordpress_ai_publisher > backups/backup_$$(date +%Y%m%d_%H%M%S).sql
	@echo "Database backed up to backups/"

clean:
	docker-compose down -v
	@echo "All containers and volumes removed"

rebuild: clean build up
	@echo "Rebuild complete!"