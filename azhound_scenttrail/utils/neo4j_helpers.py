import json
from typing import Dict, Any
from neo4j import GraphDatabase
from dataclasses import dataclass

@dataclass
class Neo4jConfig:
    """Configuration for Neo4j database operations."""
    database: str = 'neo4j'


class Neo4jGraphManager:
    """
    Manages Azure-related graph operations in Neo4j database.
    """
    
    def __init__(self, driver: GraphDatabase, config: Neo4jConfig = Neo4jConfig()):
        """
        Initialize the graph manager.
        
        Args:
            driver (GraphDatabase): Neo4j driver instance
            config (Neo4jConfig): Configuration for Neo4j operations
        """
        self.driver = driver
        self.config = config

    def add_role_def_node(self, roledef: Dict[str, Any]) -> None:
        """
        Add or update a role definition node.
        
        Args:
            roledef (Dict[str, Any]): Role definition data
        """
        properties = roledef['data']['properties']
        self.driver.execute_query(
            '''
            MERGE (:AZRBACRole {
                objectid: $object_id,
                displayname: $display_name,
                description: $description,
                isbuiltin: $is_builtin,
                tenantid: $tenant_id,
                scopes: $scopes
            })
            ''',
            object_id=roledef['data']['id'].upper(),
            display_name=properties.get('roleName', roledef['data']['name']),
            description=properties.get('description', ''),
            is_builtin=(properties['type'] == 'BuiltInRole'),
            tenant_id=roledef['data']['tenantId'].upper(),
            scopes=json.dumps(properties['assignableScopes']),
            database_=self.config.database
        )

    def add_compute_service_node_and_rg_relationships(self, scope: str) -> None:
        """
        Add a dummy node to represent potential Azure VMs (without AAD login) that can be created
        
        Args:
            scope (str): The scope of the Azure compute service to determine what resource groups it can be deployed to
        """
        records, summary, keys = self.driver.execute_query(
            '''
            MATCH (rg:AZResourceGroup)
            WHERE rg.objectid STARTS WITH $scope
            RETURN rg.objectid AS object_id
            ''',
            scope=scope.upper(),
            database_=self.config.database
        )

        for record in records:
            record_obj = record.data()
            resource_group_id = record_obj['object_id']
            dummy_object_id = f"{resource_group_id}/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/DUMMY-NEW-VM"
            self.driver.execute_query(
                '''
                MERGE (rg:AZResourceGroup {objectid: $object_id})
                MERGE (vm:AZVM {
                    aadenabled: $aad_enabled,
                    id: $id,
                    name: $name,
                    objectid: $vm_object_id,
                    operatingsystem: $os,
                    tenantid: $tenant_id
                })
                MERGE (rg)-[:AZContains]->(vm)
                ''',
                object_id=resource_group_id,
                aad_enabled=False,
                id="00000000-0000-0000-0000-000000000000",
                name="DUMMY-NEW-VM",
                vm_object_id=dummy_object_id,
                os="Any",
                tenant_id=scope.split('/')[2].upper(),
                database_=self.config.database
            )

    def add_compute_service_with_aad_login_node_and_rg_relationships(self, scope: str) -> None:
        """
        Add a dummy node to represent potential Azure VMs (with AAD login) that can be created
        
        Args:
            scope (str): The scope of the Azure compute service to determine what resource groups it can be deployed to
        """
        records, summary, keys = self.driver.execute_query(
            '''
            MATCH (rg:AZResourceGroup)
            WHERE rg.objectid STARTS WITH $scope
            RETURN rg.objectid AS object_id
            ''',
            scope=scope.upper(),
            database_=self.config.database
        )

        for record in records:
            record_obj = record.data()
            resource_group_id = record_obj['object_id']
            dummy_object_id = f"{resource_group_id}/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/DUMMY-NEW-VM"
            self.driver.execute_query(
                '''
                MERGE (rg:AZResourceGroup {objectid: $object_id})
                MERGE (vm:AZVM {
                    aadenabled: $aad_enabled,
                    id: $id,
                    name: $name,
                    objectid: $vm_object_id,
                    operatingsystem: $os,
                    tenantid: $tenant_id
                })
                MERGE (rg)-[:AZContains]->(vm)
                ''',
                object_id=resource_group_id,
                aad_enabled=True,
                id="00000000-0000-0000-0000-000000000000",
                name="DUMMY-NEW-VM",
                vm_object_id=dummy_object_id,
                os="Any",
                tenant_id=scope.split('/')[2].upper(),
                database_=self.config.database
            )

    def add_assignment_relationship(self, principal_id: str, roledef_id: str) -> None:
        """
        Create a role assignment relationship between a principal and a role.
        
        Args:
            principal_id (str): ID of the principal
            roledef_id (str): ID of the role definition
        """
        self.driver.execute_query(
            '''
            MATCH (role:AZRBACRole) 
            WHERE role.objectid CONTAINS $roledef_id
            MATCH (principal {objectid: $principal_id})
            MERGE (principal)-[:AZHasRole]->(role)
            ''',
            roledef_id=f'Microsoft.Authorization/roleDefinitions/{roledef_id}'.upper(),
            principal_id=principal_id.upper(),
            database_=self.config.database
        )

    def add_managed_identity_relationship(self, object_id: str, managed_id: str) -> None:
        """
        Create a managed identity relationship between a principal and an object.
        
        Args:
            object_id (str): ID of the object
            managed_id (str): ID of the managed identity
        """
        self.driver.execute_query(
            '''
            MATCH (object {objectid: $object_id}) 
            MATCH (principal {objectid: $managed_id})
            MERGE (object)-[:AZManagedIdentity]->(principal)
            ''',
            object_id=object_id.upper(),
            managed_id=managed_id.upper(),
            database_=self.config.database
        )

    def set_service_principal_alt_name(self, object_id: str, alt_name: str) -> None:
        """
        Set a service principal alternative name
        
        Args:
            object_id (str): ID of the service principal
            alt_name (str): The "full" object ID of a service principal
        """
        self.driver.execute_query(
            '''
            MATCH (sp:AZServicePrincipal {objectid: $object_id}) 
            SET sp.altname = $alt_name
            ''',
            object_id=object_id.upper(),
            alt_name=alt_name.upper(),
            database_=self.config.database
        )

    def add_spring_app_node(self, entity_data: Dict[str, Any]) -> None:
        """
        Add or update a Spring App entity node.
        
        Args:
            entity_data (Dict[str, Any]): Spring App entity data
        """
        properties = entity_data['data']['properties']
        self.driver.execute_query(
            '''
            MERGE (:AZSpringApp {
                objectid: $object_id,
                displayname: $display_name,
                ispublic: $is_public,
                tenantid: $tenant_id
            })
            ''',
            object_id=entity_data['data']['id'].upper(),
            display_name=properties.get('name', entity_data['data']['id'].upper()),
            is_public=properties.get('public', False),
            tenant_id=entity_data['data']['tenantId'].upper(),
            database_=self.config.database
        )

    def add_container_group_node(self, entity_data: Dict[str, Any]) -> None:
        """
        Add or update a Container Group entity node.
        
        Args:
            entity_data (Dict[str, Any]): Container Group entity data
        """
        properties = entity_data['data']['properties']
        self.driver.execute_query(
            '''
            MERGE (:AZContainerGroup {
                objectid: $object_id,
                displayname: $display_name,
                tenantid: $tenant_id
            })
            ''',
            object_id=entity_data['data']['id'].upper(),
            display_name=properties.get('name', entity_data['data']['id'].upper()),
            tenant_id=entity_data['data']['tenantId'].upper(),
            database_=self.config.database
        )

    def add_container_app_node(self, entity_data: Dict[str, Any]) -> None:
        """
        Add or update a Container App entity node.
        
        Args:
            entity_data (Dict[str, Any]): Container App entity data
        """
        properties = entity_data['data']['properties']
        self.driver.execute_query(
            '''
            MERGE (:AZContainerApp {
                objectid: $object_id,
                displayname: $display_name,
                ispublic: $is_public,
                tenantid: $tenant_id
            })
            ''',
            object_id=entity_data['data']['id'].upper(),
            display_name=properties.get('name', entity_data['data']['id'].upper()),
            is_public=properties.get('configuration', {}).get('ingress', {}).get('external', False),
            tenant_id=entity_data['data']['tenantId'].upper(),
            database_=self.config.database
        )

    def add_container_app_managed_by_relationship(self, app_id: str, manager_id: str) -> None:
        """
        Create a managedBy relationship between a container app and an object.
        
        Args:
            app_id: Container App ID
            manager_id: ID of the managing object
        """
        self.driver.execute_query(
            '''
            MATCH (app:AZContainerApp {objectid: $object_id}) 
            MATCH (manager {objectid: $manager_id})
            MERGE (app_id)-[:AZManagedBy]->(manager)
            ''',
            app_id=app_id.upper(),
            manager_id=manager_id.upper(),
            database_=self.config.database
        )

    def add_openshift_cluster_node(self, entity_data: Dict[str, Any]) -> None:
        """
        Add or update an OpenShift cluster entity node.
        
        Args:
            entity_data (Dict[str, Any]): OpenShift cluster entity data
        """
        properties = entity_data['data']['properties']
        self.driver.execute_query(
            '''
            MERGE (:AZRedHatOpenShiftCluster {
                objectid: $object_id,
                displayname: $display_name,
                ispublic: $is_public,
                tenantid: $tenant_id
            })
            ''',
            object_id=entity_data['data']['id'].upper(),
            display_name=properties.get('name', entity_data['data']['id'].upper()),
            is_public=(properties.get('apiServerProfile', {}).get('visibility', 'Private') == 'Public'),
            tenant_id=entity_data['data']['tenantId'].upper(),
            database_=self.config.database
        )

    def add_service_fabric_cluster_app_node(self, entity_data: Dict[str, Any]) -> None:
        """
        Add or update an Service Fabric Cluster App entity node.
        
        Args:
            entity_data (Dict[str, Any]): Service Fabric Cluster App entity data
        """
        properties = entity_data['data']['properties']
        self.driver.execute_query(
            '''
            MERGE (:AZServiceFabricClusterApp {
                objectid: $object_id,
                displayname: $display_name,
                tenantid: $tenant_id
            })
            ''',
            object_id=entity_data['data']['id'].upper(),
            display_name=properties.get('name', entity_data['data']['id'].upper()),
            tenant_id=entity_data['data']['tenantId'].upper(),
            database_=self.config.database
        )

    def add_owner_relationship(self, scope: str, principal_id: str) -> None:
        """
        Create an ownership relationship between a principal and a resource.
        
        Args:
            scope (str): Resource scope
            principal_id (str): ID of the principal
        """
        self.driver.execute_query(
            '''
            MATCH (resource {objectid: $scope})
            MATCH (principal {objectid: $principal_id})
            MERGE (principal)-[:AZOwns]->(resource)
            ''',
            scope=scope.upper(),
            principal_id=principal_id.upper(),
            database_=self.config.database
        )

    def add_access_admin_relationship(self, scope: str, principal_id: str) -> None:
        """
        Create an access administrator relationship between a principal and a resource.
        
        Args:
            scope (str): Resource scope
            principal_id (str): ID of the principal
        """
        self.driver.execute_query(
            '''
            MATCH (resource {objectid: $scope})
            MATCH (principal {objectid: $principal_id})
            MERGE (principal)-[:AZUserAccessAdministrator]->(resource)
            ''',
            scope=scope.upper(),
            principal_id=principal_id.upper(),
            database_=self.config.database
        )

    def set_vm_aad_node(self, vm_id: str, aad_enabled: bool) -> None:
        """
        Update a VM node with an AAD property.
        
        Args:
            vm_id (str): ID of the VM
            aad_enabled (bool): Whether AAD is enabled for the VM
        """
        self.driver.execute_query(
            '''
            MATCH (vm:AZVM {objectid: $vm_id}) 
            SET vm.aadenabled = $aad_enabled
            ''',
            vm_id=vm_id.upper(),
            aad_enabled=aad_enabled,
            database_=self.config.database
        )

    def add_vm_create_relationship(self, scope: str, principal_id: str) -> None:
        """
        Create a VM create relationship between a principal and a VM.
        
        Args:
            scope (str): VM scope
            principal_id (str): ID of the principal
        """
        self.driver.execute_query(
            '''
            MATCH (vm:AZVM) 
            WHERE vm.objectid STARTS WITH $scope AND vm.id="00000000-0000-0000-0000-000000000000" AND vm.aadenabled = false
            MATCH (principal {objectid: $principal_id})
            MERGE (principal)-[:AZVMCreate]->(vm)
            ''',
            scope=scope.upper(),
            principal_id=principal_id.upper(),
            database_=self.config.database
        )

    def add_vm_create_with_aad_login_relationship(self, scope: str, principal_id: str) -> None:
        """
        Create a VM create relationship between a principal and a VM.
        
        Args:
            scope (str): VM scope
            principal_id (str): ID of the principal
        """
        self.driver.execute_query(
            '''
            MATCH (vm:AZVM) 
            WHERE vm.objectid STARTS WITH $scope AND vm.id="00000000-0000-0000-0000-000000000000" AND vm.aadenabled = true
            MATCH (principal {objectid: $principal_id})
            MERGE (principal)-[:AZVMCreate]->(vm)
            ''',
            scope=scope.upper(),
            principal_id=principal_id.upper(),
            database_=self.config.database
        )

    def add_vm_exec_relationship(self, scope: str, principal_id: str) -> None:
        """
        Create a VM contributor relationship between a principal and a VM.
        
        Args:
            scope (str): VM scope
            principal_id (str): ID of the principal
        """
        self.driver.execute_query(
            '''
            MATCH (vm:AZVM) 
            WHERE vm.objectid STARTS WITH $scope
            MATCH (principal {objectid: $principal_id})
            MERGE (principal)-[:AZVMContributor]->(vm)
            ''',
            scope=scope.upper(),
            principal_id=principal_id.upper(),
            database_=self.config.database
        )

    def add_vm_login_relationship(self, scope: str, principal_id: str) -> None:
        """
        Create a VM login relationship between a principal and a VM.
        
        Args:
            scope (str): VM scope
            principal_id (str): ID of the principal
        """
        self.driver.execute_query(
            '''
            MATCH (vm:AZVM) 
            WHERE vm.objectid STARTS WITH $scope AND vm.aadenabled = true
            MATCH (principal {objectid: $principal_id})
            MERGE (principal)-[:AZVMLogin]->(vm)
            ''',
            scope=scope.upper(),
            principal_id=principal_id.upper(),
            database_=self.config.database
        )

    def add_vm_update_relationship(self, scope: str, principal_id: str) -> None:
        """
        Create a VM update relationship between a principal and a VM.
        
        Args:
            scope (str): VM scope
            principal_id (str): ID of the principal
        """
        self.driver.execute_query(
            '''
            MATCH (vm:AZVM) 
            WHERE vm.objectid STARTS WITH $scope
            MATCH (principal {objectid: $principal_id})
            MERGE (principal)-[:AZVMUpdate]->(vm)
            ''',
            scope=scope.upper(),
            principal_id=principal_id.upper(),
            database_=self.config.database
        )

    def add_assign_managed_identity_relationship(self, scope: str, principal_id: str) -> None:
        """
        Create an assign identity relationship between a principal and a service principal.
        
        Args:
            scope (str): Service principal scope
            principal_id (str): ID of the principal
        """
        self.driver.execute_query(
            '''
            MATCH (sp:AZServicePrincipal) 
            WHERE sp.altname STARTS WITH $scope AND sp.serviceprincipaltype = 'ManagedIdentity'
            MATCH (principal {objectid: $principal_id})
            MERGE (principal)-[:AZAssignIdentity]->(sp)
            ''',
            scope=scope.upper(),
            principal_id=principal_id.upper(),
            database_=self.config.database
        )

# For backward compatibility
def add_role_def_node(driver: GraphDatabase, roledef: Dict[str, Any]) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_role_def_node(roledef)

def add_compute_service_node_and_rg_relationships(driver: GraphDatabase, scope: str) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_compute_service_node_and_rg_relationships(scope)

def add_compute_service_with_aad_login_node_and_rg_relationships(driver: GraphDatabase, scope: str) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_compute_service_with_aad_login_node_and_rg_relationships(scope)

def add_assignment_relationship(driver: GraphDatabase, principal_id: str, roledef_id: str) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_assignment_relationship(principal_id, roledef_id)

def add_managed_identity_relationship(driver: GraphDatabase, object_id: str, managed_id: str) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_managed_identity_relationship(object_id, managed_id)

def set_service_principal_alt_name(driver: GraphDatabase, object_id: str, alt_name: str) -> None:
    manager = Neo4jGraphManager(driver)
    manager.set_service_principal_alt_name(object_id, alt_name)

def add_spring_app_node(driver: GraphDatabase, entity_data: Dict[str, Any]) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_spring_app_node(entity_data)

def add_container_group_node(driver: GraphDatabase, entity_data: Dict[str, Any]) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_container_group_node(entity_data)

def add_container_app_node(driver: GraphDatabase, entity_data: Dict[str, Any]) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_container_app_node(entity_data)

def add_container_app_managed_by_relationship(driver: GraphDatabase, app_id: str, manager_id: str) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_container_app_managed_by_relationship(app_id, manager_id)

def add_openshift_cluster_node(driver: GraphDatabase, entity_data: Dict[str, Any]) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_openshift_cluster_node(entity_data)

def add_service_fabric_cluster_app_node(driver: GraphDatabase, entity_data: Dict[str, Any]) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_service_fabric_cluster_app_node(entity_data)

def add_owner_relationship(driver: GraphDatabase, scope: str, principal_id: str) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_owner_relationship(scope, principal_id)

def add_access_admin_relationship(driver: GraphDatabase, scope: str, principal_id: str) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_access_admin_relationship(scope, principal_id)

def add_vm_create_relationship(driver: GraphDatabase, scope: str, principal_id: str) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_vm_create_relationship(scope, principal_id) 

def add_vm_create_with_aad_login_relationship(driver: GraphDatabase, scope: str, principal_id: str) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_vm_create_with_aad_login_relationship(scope, principal_id)   

def add_vm_exec_relationship(driver: GraphDatabase, scope: str, principal_id: str) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_vm_exec_relationship(scope, principal_id)

def set_vm_aad_node(driver: GraphDatabase, vm_id: str, aad_enabled: bool) -> None:
    manager = Neo4jGraphManager(driver)
    manager.set_vm_aad_node(vm_id, aad_enabled)

def add_vm_login_relationship(driver: GraphDatabase, scope: str, principal_id: str) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_vm_login_relationship(scope, principal_id)

def add_vm_update_relationship(driver: GraphDatabase, scope: str, principal_id: str) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_vm_update_relationship(scope, principal_id)

def add_assign_managed_identity_relationship(driver: GraphDatabase, scope: str, principal_id: str) -> None:
    manager = Neo4jGraphManager(driver)
    manager.add_assign_managed_identity_relationship(scope, principal_id)