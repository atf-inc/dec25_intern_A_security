#!/bin/bash
# scripts/create_structure.sh

mkdir -p quantumshield/{config/{tool_configs,ml_configs,policies},core,integrations,detection_engines}
mkdir -p quantumshield/{ml_models/{traffic_classifier,anomaly_detector,ddos_predictor,malware_detector,zero_day_detector,attack_pattern_recognizer,ensemble}}
mkdir -p quantumshield/{data_pipeline,threat_intelligence,network_layer,application_layer,response_system,adaptive_learning}
mkdir -p quantumshield/{monitoring,database,api/endpoints,cli/commands,web_dashboard/{frontend,backend}}
mkdir -p quantumshield/{tests/{unit,integration,fixtures/{sample_pcaps,attack_samples,benign_traffic}}}
mkdir -p quantumshield/{scripts,datasets/{raw,processed,labeled},models,logs,docs}

echo "Project structure created successfully!"

