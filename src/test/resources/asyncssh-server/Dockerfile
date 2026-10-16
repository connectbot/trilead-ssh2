FROM python:3.15-slim-bookworm AS builder
RUN apt-get update && \
    apt-get install -y gcc openssh-server && \
    apt-get clean
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --user -r requirements.txt
RUN mkdir -p /app/etc/ssh && ssh-keygen -A -f /app
COPY . /app

FROM python:3.15-slim-bookworm AS app
COPY --from=builder /app/etc/ssh /app/etc/ssh
COPY --from=builder /root/.local /app/.local
COPY --from=builder /app/server.py /app/server.py

USER root
RUN groupadd -g 1234 testserver && \
    useradd -m -u 1234 -g testserver -d /app testserver && \
    chown -R testserver:testserver /app
WORKDIR /app
USER 1234:1234

EXPOSE 8022
ENV PYTHONUNBUFFERED=0
CMD ["python", "-u", "server.py"]
COPY *.pub /app/
RUN cat /app/*.pub > /app/authorized_keys && rm -f /app/*.pub
