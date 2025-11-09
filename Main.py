import json
import sys
from collections import defaultdict

def load_data():
    with open('enterprise-attack.json') as f:
        data = json.load(f)

    groups = {}
    techniques = {}
    tactics = {}
    relationships = []

    for obj in data['objects']:
        obj_type = obj.get('type')

        if obj_type == 'intrusion-set':
            groups[obj['id']] = obj

        if obj_type == 'attack-pattern':
            techniques[obj['id']] = obj

        if obj_type == 'x-mitre-tactic':
            tactics[obj['id']] = obj

        if obj_type == 'relationship':
            relationships.append(obj)
    return groups, techniques, tactics, relationships


def build_mappings(groups, techniques, relationships):
    group_to_techniques = defaultdict(list)
    technique_to_groups = defaultdict(list)

    for rel in relationships:
        if rel.get('relationship_type') == 'uses':
            source = rel.get('source_ref')
            target = rel.get('target_ref')
            if source in groups and target in techniques:
                group_to_techniques[source].append(target)
                technique_to_groups[target].append(source)
    return group_to_techniques, technique_to_groups

def get_mitre_id(obj):
    for ref in obj.get('external_references',[]):
        if ref.get('source_name') == "mitre-attack":
            return ref.get('external_id')

    return None

def group_search(group_name, groups, techniques, tactics, group_to_techniques):
    matches = []

    for group_id, group in groups.items():
        if group_name.lower() in group.get('name', '').lower():
            matches.append((group_id, group))

    if len(matches) == 0:
        print("No groups found")
        return

    group_id, group = matches[0]

    print("\n")
    print(f"Group: {group.get('name')}")
    print(f"ID: {get_mitre_id(group)}")

    tech_ids = group_to_techniques.get(group_id, [])
    print(f"\nTechniques used ({len(tech_ids)} total):")

    for tech_id in tech_ids:
        tech = techniques.get(tech_id)
        if tech:
            print(f"\t{get_mitre_id(tech)}: {tech.get('name')}")


def technique_search(technique_name, groups, techniques, technique_to_groups):
    matches = []

    # Find matching techniques
    for tech_id, tech in techniques.items():
        tech_name = tech.get('name', '')
        mitre_id = get_mitre_id(tech)

        # Check if search term matches name or ID
        if (technique_name.lower() in tech_name.lower() or
                technique_name.upper() == mitre_id):
            matches.append((tech_id, tech))

    if len(matches) == 0:
        print("No techniques found")
        return

    # Show first match
    tech_id, tech = matches[0]

    print(f"Technique: {tech.get('name')}")
    print(f"ID: {get_mitre_id(tech)}")

    # Get groups using this technique
    group_ids = technique_to_groups.get(tech_id, [])
    print(f"\nGroups using this technique ({len(group_ids)} total):")

    # Loop through and print each group
    for group_id in group_ids:
        group = groups.get(group_id)
        if group:
            print(f"\t{get_mitre_id(group)}: {group.get('name')}")

def cli_tool():
    print("Loading data...")
    groups, techniques, tactics, relationships = load_data()
    g2t, t2g = build_mappings(groups, techniques, relationships)
    print("Ready!")
    while True:
        print("\n")
        print("Commands: \n")
        print("group <name>     -Search for a group \n")
        print("technique <name> -Search for a technique \n")
        print("quit             -Exit \n")
        user_input = input("> ").strip()
        parts = user_input.split()
        if len(parts) == 0:
            continue
        command = parts[0].lower()

        if user_input == "quit":
            exit(0)
            print("\n")
        elif command == "group":
            if len(parts) < 2:
                print("Usage: group <name> \n")
                continue
            group_name = ' '.join(parts[1:])
            group_search(group_name, groups, techniques, tactics, g2t)
        elif command == "technique":
            if len(parts) < 2:
                print("Usage: technique <name> \n")
                continue
            tech_name = ' '.join(parts[1:])  # Join all words after 'technique'
            technique_search(tech_name, groups, techniques, t2g)
        else:
            print("Unknown command... \n")

if __name__ == "__main__":

    cli_tool()
