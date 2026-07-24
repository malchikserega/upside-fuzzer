import json
import sys

def sanitize(swagger_path):
    with open(swagger_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    if 'paths' in data:
        for path, path_item in data['paths'].items():
            for method, operation in path_item.items():
                if isinstance(operation, dict) and 'parameters' in operation:
                    new_params = []
                    for param in operation['parameters']:
                        # Remove parameters that are 'deepObject' or have nested properties in schema
                        if param.get('in') == 'query':
                            if param.get('style') == 'deepObject':
                                continue
                            if 'schema' in param:
                                schema = param['schema']
                                if schema.get('type') == 'object' or 'properties' in schema or '$ref' in schema:
                                    continue
                        new_params.append(param)
                    operation['parameters'] = new_params

    with open(swagger_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

if __name__ == "__main__":
    sanitize(sys.argv[1])
