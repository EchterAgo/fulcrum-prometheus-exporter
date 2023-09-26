# Fulcrum Prometheus Exporter

## README 

### Introduction
This repository is a fork of the [original Fulcrum Prometheus Exporter](https://github.com/EchterAgo/fulcrum-prometheus-exporter) by Axel Gembe. The original project appears to be abandoned, and this fork aims to continue its development and maintenance.

### Why Fork?
- The original repository is not actively maintained.
- To add new features and optimizations.
- To fix existing issues and improve documentation.

### Features
- Exports Fulcrum metrics to Prometheus.
- Easy to set up and configure.
- Written in Python.

### Quick Start
1. Clone this repository.
   ```
   git clone https://github.com/federicociro/fulcrum-prometheus-exporter.git
   ```
2. Install the required Python packages.
   ```
   pip install -r requirements.txt
   ```
3. Run the exporter.
   ```
   python fulcrum-monitor.py
   ```

## Configuration Options

The script can be configured using command-line arguments, environment variables, or hardcoded default values. The priority is as follows:

1. **Command-Line Arguments**: Take the highest precedence.
2. **Environment Variables**: Used if no command-line argument is provided for that option.
3. **Hardcoded Defaults**: Used if neither command-line arguments nor environment variables are provided.

### Command-Line Arguments

| Argument                | Description                  | Example                       |
|-------------------------|------------------------------|-------------------------------|
| `--fulcrum-stats-url`   | Fulcrum stats URL            | `http://localhost:8080/stats` |
| `--metrics-addr`        | Metrics address              | `0.0.0.0`                     |
| `--metrics-port`        | Metrics port                 | `8080`                        |
| `--retries`             | Number of retries            | `3`                           |
| `--timeout`             | Timeout in seconds           | `20`                          |
| `--log-level`           | Log level                    | `DEBUG`                       |

### Environment Variables

| Variable                 | Description                  | Default                       |
|--------------------------|------------------------------|-------------------------------|
| `FULCRUM_STATS_URL`      | Fulcrum stats URL            | `http://127.0.0.1:8080/stats` |
| `METRICS_ADDR`           | Metrics address              | `""` (any address)            |
| `METRICS_PORT`           | Metrics port                 | `50039`                       |
| `RETRIES`                | Number of retries            | `5`                           |
| `TIMEOUT`                | Timeout in seconds           | `30`                          |
| `LOG_LEVEL`              | Log level                    | `INFO`                        |

### Hardcoded Defaults

If neither command-line arguments nor environment variables are provided, the script falls back to hardcoded default values. These are specified in the script and serve as the last-resort configuration options.

### Example Usage

To run the script with custom settings:

```
python fulcrum-monitor.py --fulcrum-stats-url http://localhost:8080/stats --metrics-addr 0.0.0.0 --metrics-port 8080 --retries 3 --timeout 20 --log-level DEBUG
```


#### Contributing
We welcome contributions from the community. Please read the [contribution guidelines](CONTRIBUTING.md) for more information.

#### License
This project is licensed under the [BSD 3-Clause License](https://github.com/federicociro/fulcrum-prometheus-exporter/blob/master/LICENSE).
