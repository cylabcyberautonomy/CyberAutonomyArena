FROM incalmo/attacker:latest

ENV PYTHONUNBUFFERED=1

COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 8888

CMD ["/start.sh"]
