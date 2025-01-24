import argparse
import configparser
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from os.path import exists
from neo4j import GraphDatabase
from pathlib import Path
import utils.analysis_utils as analysis_utils
import utils.neo4j_helpers as neo4j_helpers
from functools import lru_cache
from typing import Dict, Set, List
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AzureRoleAnalyzer:
    # Using frozen sets for better performance
    ACCESS_ADMIN_ACTIONS = [
        frozenset(['microsoft.authorization/roleassignments/write']),
        frozenset(['microsoft.authorization/roledefinitions/write'])
    ]

    VM_EXEC_ACTIONS = [
        frozenset(['microsoft.compute/virtualmachines/runcommand/action']),
        frozenset(['microsoft.compute/virtualmachines/runcommands/read',
                   'microsoft.compute/virtualmachines/runcommands/write',
                   'microsoft.resources/subscriptions/resourcegroups/read']),
        frozenset(['microsoft.compute/sshpublickeys/write',
                   'microsoft.compute/virtualmachines/read',
                   'microsoft.compute/virtualmachines/extensions/write'])
    ]

    VM_EXEC_DATA_ACTIONS = [
        frozenset(['microsoft.compute/virtualmachines/login/action']),
        frozenset(['microsoft.compute/virtualmachines/loginasadmin/action'])
    ]

    VM_UPDATE_ACTIONS = frozenset(['microsoft.compute/virtualmachines/read',
                                   'microsoft.compute/virtualmachines/write'])

    VM_CREATE_ACTIONS = frozenset([
        'microsoft.compute/virtualmachines/read',
        'microsoft.compute/virtualmachines/write',
        'microsoft.managedidentity/userassignedidentities/assign/action',
        'microsoft.network/networkinterfaces/join/action',
        'microsoft.network/networkinterfaces/read',
        'microsoft.network/networkinterfaces/write',
        'microsoft.network/networksecuritygroups/join/action',
        'microsoft.network/networksecuritygroups/read',
        'microsoft.network/networksecuritygroups/write',
        'microsoft.network/publicipaddresses/join/action',
        'microsoft.network/publicipaddresses/read',
        'microsoft.network/publicipaddresses/write',
        'microsoft.network/virtualnetworks/read',
        'microsoft.network/virtualnetworks/subnets/join/action',
        'microsoft.network/virtualnetworks/write',
        'microsoft.resources/deployments/operationstatuses/read',
        'microsoft.resources/deployments/read',
        'microsoft.resources/deployments/write',
        'microsoft.resources/subscriptions/resourcegroups/read',
    ])

    VM_CREATE_AADLOGIN_ACTIONS = frozenset([
        'microsoft.compute/virtualmachines/extensions/read',
        'microsoft.compute/virtualmachines/extensions/write',
        'microsoft.compute/virtualmachines/read',
        'microsoft.compute/virtualmachines/write',
        'microsoft.managedidentity/userassignedidentities/assign/action',
        'microsoft.network/networkinterfaces/join/action',
        'microsoft.network/networkinterfaces/read',
        'microsoft.network/networkinterfaces/write',
        'microsoft.network/networksecuritygroups/join/action',
        'microsoft.network/networksecuritygroups/read',
        'microsoft.network/networksecuritygroups/write',
        'microsoft.network/publicipaddresses/join/action',
        'microsoft.network/publicipaddresses/read',
        'microsoft.network/publicipaddresses/write',
        'microsoft.network/virtualnetworks/read',
        'microsoft.network/virtualnetworks/subnets/join/action',
        'microsoft.network/virtualnetworks/write',
        'microsoft.resources/deployments/operationstatuses/read',
        'microsoft.resources/deployments/read'
        'microsoft.resources/deployments/write',
        'microsoft.resources/subscriptions/resourcegroups/read',
    ])

    ASSIGN_MANAGED_IDENTITY_ACTIONS = frozenset(['microsoft.managedidentity/userassignedidentities/assign/action'])

    EXCLUDED_ADMIN_ROLES = frozenset({
        'bda0d508-adf1-4af0-9c28-88919fc3ae06',
        '8b54135c-b56d-4d72-a534-26097cfdc8d8',
        '66f75aeb-eabe-4b70-9f1e-c350c4c9ad04',
        '0f641de8-0b88-4198-bdef-bd8b45ceba96',
        '5a382001-fe36-41ff-bba4-8bf06bd54da9',
        '8480c0f0-4509-4229-9339-7c10018cb8c4',
        '95dd08a6-00bd-4661-84bf-f6726f83a4d0',
        '95de85bd-744d-4664-9dde-11430bc34793'
    })

    def __init__(self):
        self.config = self._load_config()
        self.neo4j_uri = f"neo4j://{self.config['neo4j_hostname']}:{self.config['neo4j_port']}"
        self.neo4j_auth = (self.config['neo4j_user'], self.config['neo4j_password'])
        self.azure_services = self._fetch_azure_operations()
        self.neo4j_manager = neo4j_helpers.Neo4jGraphManager(
            GraphDatabase.driver(self.neo4j_uri, auth=self.neo4j_auth)
        )

    @lru_cache(maxsize=1)
    def _load_config(self) -> Dict:
        """Load and cache configuration from config.ini file"""
        config_paths = [
            Path.cwd() / 'config.ini',
            Path.cwd().parent / 'config.ini',
            Path(__file__).parent.parent.parent / 'config.ini',
            Path.home() / 'config.ini'
        ]
        
        for config_path in config_paths:
            if config_path.exists():
                config = configparser.ConfigParser()
                config.read(config_path)
                
                if 'DEFAULT' not in config:
                    raise KeyError("Configuration must contain a DEFAULT section")
                
                required_keys = ['neo4j_hostname', 'neo4j_port', 'neo4j_user', 'neo4j_password']
                missing_keys = [key for key in required_keys if key not in config['DEFAULT']]
                
                if missing_keys:
                    raise KeyError(f"Missing required configuration keys: {', '.join(missing_keys)}")
                
                return dict(config['DEFAULT'])
                
        raise FileNotFoundError(
            f"config.ini not found in any of these locations:\n{chr(10).join(map(str, config_paths))}"
        )

    @lru_cache(maxsize=1)
    def _fetch_azure_operations(self) -> Dict:
        """Cache Azure operations data"""
        url = "https://raw.githubusercontent.com/iann0036/iam-dataset/refs/heads/main/azure/provider-operations.json"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Failed to fetch Azure operations: {e}")
            raise

    def _process_roledef_batch(self, roledefs_batch: List[Dict]) -> List[tuple]:
        """Process a batch of role definitions"""
        results = []
        for roledef in roledefs_batch:
            effective_actions = analysis_utils.process_effective(roledef, self.azure_services)
            roledef_id = roledef['data']['name']
            result = {
                'owner': False,
                'access_admin': False,
                'vm_create': False,
                'vm_create_with_aad_login': False,
                'vm_exec': False,
                'vm_login': False,
                'vm_update': False,
                'assign_managed_identity': False
            }

            if effective_actions['is_owner_policy']:
                result['owner'] = True
                self.neo4j_manager.add_role_def_node(roledef)
            else:
                permitted_actions_set = set([perm_action['name'].lower() for perm_action in effective_actions.get('permitted_actions', [])])
                permitted_data_actions_set = set([perm_action['name'].lower() for perm_action in effective_actions.get('permitted_data_actions', [])])
                
                if any(action_set.issubset(permitted_actions_set) for action_set in self.ACCESS_ADMIN_ACTIONS):
                    self.neo4j_manager.add_role_def_node(roledef)
                    result['access_admin'] = True
                if any(action_set.issubset(permitted_actions_set) for action_set in self.VM_EXEC_ACTIONS):
                    self.neo4j_manager.add_role_def_node(roledef)
                    result['vm_exec'] = True
                if self.VM_CREATE_ACTIONS.issubset(permitted_actions_set):
                    self.neo4j_manager.add_role_def_node(roledef)
                    result['vm_create'] = True
                if self.VM_CREATE_AADLOGIN_ACTIONS.issubset(permitted_actions_set):
                    self.neo4j_manager.add_role_def_node(roledef)
                    result['vm_create_with_aad_login'] = True
                if any(action_set.issubset(permitted_data_actions_set) for action_set in self.VM_EXEC_DATA_ACTIONS):
                    self.neo4j_manager.add_role_def_node(roledef)
                    result['vm_login'] = True
                if self.VM_UPDATE_ACTIONS.issubset(permitted_actions_set):
                    self.neo4j_manager.add_role_def_node(roledef)
                    result['vm_update'] = True
                if self.ASSIGN_MANAGED_IDENTITY_ACTIONS.issubset(permitted_actions_set):
                    self.neo4j_manager.add_role_def_node(roledef)
                    result['assign_managed_identity'] = True
            if roledef_id not in self.EXCLUDED_ADMIN_ROLES:
                results.append((roledef_id, result))
        return results

    def process_role_definitions(self, filename: str) -> Dict[str, Set[str]]:
        """Process role definitions using batched processing"""
        with open(filename) as f:
            roledefs = json.load(f)['data']

        # Process in batches for better efficiency
        BATCH_SIZE = 50
        batches = [roledefs[i:i + BATCH_SIZE] for i in range(0, len(roledefs), BATCH_SIZE)]
        
        owner_roles = set()
        access_admin_roles = set()
        vm_create_roles = set()
        vm_create_with_aad_login_roles = set()
        vm_exec_roles = set()
        vm_login_roles = set()
        vm_update_roles = set()
        assign_managed_identity_roles = set()

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self._process_roledef_batch, batch) for batch in batches]
            
            for future in as_completed(futures):
                for roledef_id, result in future.result():
                    if result['owner']:
                        owner_roles.add(roledef_id)
                    if result['access_admin']:
                        access_admin_roles.add(roledef_id)
                    if result['vm_create']:
                        vm_create_roles.add(roledef_id)
                    if result['vm_create_with_aad_login']:
                        vm_create_with_aad_login_roles.add(roledef_id)
                    if result['vm_exec']:
                        vm_exec_roles.add(roledef_id)
                    if result['vm_login']:
                        vm_login_roles.add(roledef_id)
                    if result['vm_update']:
                        vm_update_roles.add(roledef_id)
                    if result['assign_managed_identity']:
                        assign_managed_identity_roles.add(roledef_id)

        return {
            "owner_roles": owner_roles,
            "access_admin_roles": access_admin_roles,
            "vm_create_roles": vm_create_roles,
            "vm_create_with_aad_login_roles": vm_create_with_aad_login_roles,
            "vm_exec_roles": vm_exec_roles,
            "vm_login_roles": vm_login_roles,
            "vm_update_roles": vm_update_roles,
            "assign_managed_identity_roles": assign_managed_identity_roles
        }

    def process_azhound_file(self, filename: str, interesting_roles: Dict[str, Set[str]]) -> None:
        """Process AzureHound output file with improved batch processing"""
        def process_entity_batch(entities_batch: List[Dict]) -> Set[str]:
            assignments = set()
            for entity in entities_batch:
                if "RoleAssignment" in entity['kind'] and entity['kind'] != "AZRoleAssignment":
                    role_assignments = entity['data'].get('roleAssignments', [])
                    assignments.update(
                        json.dumps(assignment['roleAssignment'], sort_keys=True)
                        for assignment in role_assignments
                    )
                elif entity['kind'] == "AZVM":
                    vm_id = entity['data']['id']
                    aad_enabled = False
                    if "resources" in entity['data']:
                        for resource in entity['data']['resources']:
                            if "properties" in resource['properties']:
                                publisher = resource['properties'].get('publisher', '')
                                if publisher == "Microsoft.Azure.ActiveDirectory":
                                    aad_enabled = True
                                    break
                    self.neo4j_manager.set_vm_aad_node(vm_id, aad_enabled)
                elif entity['kind'] == "AZServicePrincipal" and \
                    "alternativeNames" in entity['data'] and \
                    "isExplicit=True" in entity['data']['alternativeNames']:
                    for alt_name in entity['data']['alternativeNames']:
                        if "/subscriptions" in alt_name:
                            self.neo4j_manager.set_service_principal_alt_name(entity['data']['id'], alt_name)
                elif entity['kind'] == "AZSpringApp":
                    self.neo4j_manager.add_spring_app_node(entity)

                    self.neo4j_manager.add_managed_identity_relationship(entity['data']['id'], entity['data']['identity'].get('principalId', ''))
                    user_assigned_ids = entity['data']['identity'].get('userAssignedIdentities', {})
                    for user_assigned_id in user_assigned_ids.keys():
                        self.neo4j_manager.add_managed_identity_relationship(entity['data']['id'], user_assigned_ids[user_assigned_id]['principalId'])
                elif entity['kind'] == "AZManagedCluster":
                    service_principal_profile_obj = entity['data']['identity'].get('servicePrincipalProfile', {})
                    service_principal_profile_id = service_principal_profile_obj.get('clientId', '')
                    self.neo4j_manager.add_managed_identity_relationship(entity['data']['id'], service_principal_profile_id)

                    identity_profiles = entity['data']['identity'].get('identityProfile', {})
                    kubelet_id = identity_profiles.get('kubeletidentity', {})
                    user_assigned_id = kubelet_id.get('resourceId', '')
                    self.neo4j_manager.add_managed_identity_relationship(entity['data']['id'], user_assigned_id)
                elif entity['kind'] == "AZContainerGroup":
                    self.neo4j_manager.add_container_group_node(entity)
                    
                    self.neo4j_manager.add_managed_identity_relationship(entity['data']['id'], entity['data']['identity'].get('principalId', ''))
                    user_assigned_ids = entity['data']['identity'].get('userAssignedIdentities', {})
                    for user_assigned_id in user_assigned_ids.keys():
                        self.neo4j_manager.add_managed_identity_relationship(entity['data']['id'], user_assigned_ids[user_assigned_id]['principalId'])
                elif entity['kind'] == "AZContainerApp":
                    self.neo4j_manager.add_container_app_node(entity)
                    self.neo4j_manager.add_container_app_managed_by_relationship(entity['data']['id'], entity['data'].get('managedBy', ''))

                    self.neo4j_manager.add_managed_identity_relationship(entity['data']['id'], entity['data']['identity'].get('principalId', ''))
                    user_assigned_ids = entity['data']['identity'].get('userAssignedIdentities', {})
                    for user_assigned_id in user_assigned_ids.keys():
                        self.neo4j_manager.add_managed_identity_relationship(entity['data']['id'], user_assigned_ids[user_assigned_id]['principalId'])
                elif entity['kind'] == "AZRedHatOpenShiftCluster":
                    self.neo4j_manager.add_openshift_cluster_node(entity)
                    self.neo4j_manager.add_managed_identity_relationship(entity['data']['id'], entity['data']['identity'].get('clientId', ''))
                elif entity['kind'] == "AZServiceFabricClusterApp" or \
                    entity['kind'] == "AZServiceFabricManagedClusterApp":
                    self.neo4j_manager.add_service_fabric_cluster_app_node(entity)

                    self.neo4j_manager.add_managed_identity_relationship(entity['data']['id'], entity['data']['identity'].get('principalId', ''))
                    user_assigned_ids = entity['data']['identity'].get('userAssignedIdentities', {})
                    for user_assigned_id in user_assigned_ids.keys():
                        self.neo4j_manager.add_managed_identity_relationship(entity['data']['id'], user_assigned_ids[user_assigned_id]['principalId'])
            return assignments

        with open(filename) as f:
            data = json.load(f)['data']

        # Process in batches
        BATCH_SIZE = 100
        batches = [data[i:i + BATCH_SIZE] for i in range(0, len(data), BATCH_SIZE)]
        
        role_assignments_set = set()
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(process_entity_batch, batch) for batch in batches]
            for future in as_completed(futures):
                role_assignments_set.update(future.result())

        unique_assignments = [json.loads(assignment) for assignment in role_assignments_set]
        logger.info(f"Found {len(unique_assignments)} unique role assignments")

        # Batch process assignments
        def process_assignments_batch(assignments_batch):
            for assignment in assignments_batch:
                props = assignment['properties']
                roledef_id = props['roleDefinitionId'].split('/')[-1]
                principal_id = props['principalId']
                scope = props['scope']

                self.neo4j_manager.add_assignment_relationship(principal_id, roledef_id)

                if roledef_id in interesting_roles['owner_roles']:
                    self.neo4j_manager.add_owner_relationship(scope, principal_id)
                if roledef_id in interesting_roles['access_admin_roles']:
                    self.neo4j_manager.add_access_admin_relationship(scope, principal_id)
                if roledef_id in interesting_roles['vm_create_roles']:
                    print(f"Adding VM create relationship for {principal_id}")
                    self.neo4j_manager.add_compute_service_node_and_rg_relationships(scope)
                    self.neo4j_manager.add_vm_create_relationship(scope, principal_id)
                if roledef_id in interesting_roles['vm_create_with_aad_login_roles']:
                    print(f"Adding VM create with AAD login relationship for {principal_id}")
                    self.neo4j_manager.add_compute_service_with_aad_login_node_and_rg_relationships(scope)
                    self.neo4j_manager.add_vm_create_with_aad_login_relationship(scope, principal_id)
                if roledef_id in interesting_roles['vm_exec_roles']:
                    self.neo4j_manager.add_vm_exec_relationship(scope, principal_id)
                if roledef_id in interesting_roles['vm_login_roles']:
                    self.neo4j_manager.add_vm_login_relationship(scope, principal_id)
                if roledef_id in interesting_roles['vm_update_roles']:
                    self.neo4j_manager.add_vm_update_relationship(scope, principal_id)
                if roledef_id in interesting_roles['assign_managed_identity_roles']:
                    self.neo4j_manager.add_assign_managed_identity_relationship(scope, principal_id)

        ASSIGNMENT_BATCH_SIZE = 50
        assignment_batches = [unique_assignments[i:i + ASSIGNMENT_BATCH_SIZE] 
                            for i in range(0, len(unique_assignments), ASSIGNMENT_BATCH_SIZE)]

        with ThreadPoolExecutor() as executor:
            list(executor.map(process_assignments_batch, assignment_batches))

def main():
    parser = argparse.ArgumentParser(
        description='Insert eligible role assignments from exported PIM file')
    parser.add_argument('roledef_filename', 
                       help='JSON file with role definitions from azurehound list rbac-role-definitions')
    parser.add_argument('azurehound_filename', 
                       help='JSON file as output by the azurehound list command')
    args = parser.parse_args()

    # Validate input files
    for filename in [args.roledef_filename, args.azurehound_filename]:
        if not exists(filename):
            print(f"File {filename} doesn't exist")
            exit(1)

    analyzer = AzureRoleAnalyzer()
    
    print("Analyzing role definitions (requires manual verification for any ABAC conditions)...")
    interesting_roles = analyzer.process_role_definitions(args.roledef_filename)

    # Print findings
    print(interesting_roles)

    print("\nProcessing role assignments...")
    analyzer.process_azhound_file(args.azurehound_filename, interesting_roles)

if __name__ == "__main__":
    main()