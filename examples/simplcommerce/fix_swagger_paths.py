import sys
import json

file_path = sys.argv[1] if len(sys.argv) > 1 else 'simplcommerce_prep/swagger-sanitized.json'

with open(file_path, 'r') as f:
    spec = json.load(f)

for path_str, methods in list(spec.get('paths', {}).items()):
    for method, op in list(methods.items()):
        if method not in ['get', 'post', 'put', 'delete', 'patch']: continue
        params = op.get('parameters', [])
        
        # Check if there are parameters in 'path' that are not in the URL
        valid_params = []
        for p in params:
            if p.get('in') == 'path':
                placeholder = '{' + p['name'] + '}'
                if placeholder not in path_str:
                    print(f"Removing invalid path parameter '{p['name']}' from {method.upper()} {path_str}")
                    continue
            
            # Remove complex query parameters (Objects)
            if p.get('in') == 'query':
                schema = p.get('schema', {})
                if schema.get('type') == 'object' or '$ref' in schema:
                    print(f"Removing complex query parameter '{p['name']}' from {method.upper()} {path_str}")
                    continue
                # Also check arrays of objects
                if schema.get('type') == 'array':
                    items = schema.get('items', {})
                    if items.get('type') == 'object' or '$ref' in items:
                        print(f"Removing complex query array parameter '{p['name']}' from {method.upper()} {path_str}")
                        continue
            
            valid_params.append(p)
            
        op['parameters'] = valid_params

with open(file_path, 'w') as f:
    json.dump(spec, f, indent=2)
