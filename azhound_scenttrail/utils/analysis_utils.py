from typing import Dict, List, Union, Set
import re

class RBACRolePermissionAnalyzer:
    """
    A class to process and analyze Azure permissions and policies.
    """
    
    def __init__(self, services: List[Dict]):
        """
        Initialize with Azure services configuration.
        
        Args:
            services (List[Dict]): List of Azure service definitions
        """
        self.all_possible_actions = self._extract_possible_actions(services)
        self.services = services

    def _extract_possible_actions(self, services: List[Dict]) -> Dict[str, Set[str]]:
        """
        Extract all possible actions from services configuration.
        
        Args:
            services (List[Dict]): List of service definitions
            
        Returns:
            Dict[str, Set[str]]: Dictionary containing regular and data actions
        """
        regular_actions = set()
        data_actions = set()

        for service in services:
            # Process service operations
            self._process_operations(service.get('operations', []), regular_actions, data_actions)
            
            # Process resource type operations
            for resource_type in service.get('resourceTypes', []):
                self._process_operations(resource_type.get('operations', []), regular_actions, data_actions)

        return {
            'regular': regular_actions,
            'data': data_actions
        }

    @staticmethod
    def _process_operations(operations: List[Dict], regular_actions: Set[str], data_actions: Set[str]):
        """
        Process operations and categorize them into regular and data actions.
        
        Args:
            operations (List[Dict]): List of operations to process
            regular_actions (Set[str]): Set to store regular actions
            data_actions (Set[str]): Set to store data actions
        """
        for operation in operations:
            target_set = data_actions if operation.get('isDataAction', False) else regular_actions
            target_set.add(operation['name'].lower())

    def _match_actions(self, pattern: str, is_data_action: bool = False) -> List[Dict]:
        """
        Match actions against a pattern.
        
        Args:
            pattern (str): Pattern to match against
            is_data_action (bool): Whether to match data actions
            
        Returns:
            List[Dict]: List of matched actions
        """
        matched_actions = []
        match_expression = "^" + re.escape(pattern).replace("\\*", ".*").replace("\\?", ".{1}") + "$"

        for service in self.services:
            # Check service operations
            for operation in service.get('operations', []):
                if operation.get('isDataAction', False) == is_data_action:
                    if re.match(match_expression.lower(), operation['name'].lower()):
                        matched_actions.append({
                            'name': operation['name'],
                            'based_on': pattern,
                            'origin': operation.get('origin', '')
                        })

            # Check resource type operations
            for resource_type in service.get('resourceTypes', []):
                for operation in resource_type.get('operations', []):
                    if operation.get('isDataAction', False) == is_data_action:
                        if re.match(match_expression.lower(), operation['name'].lower()):
                            matched_actions.append({
                                'name': operation['name'],
                                'based_on': pattern,
                                'origin': operation.get('origin', '')
                            })

        return matched_actions

    def process_effective(self, custom_policy: Dict) -> Dict[str, Union[List[Dict], bool]]:
        """
        Process effective permissions from a custom policy.
        
        Args:
            custom_policy (Dict): The custom policy JSON object
            
        Returns:
            Dict[str, Union[List[Dict], bool]]: Processed permissions and owner status
        """
        permitted_actions = []
        permitted_data_actions = []
        
        permissions = custom_policy.get('data', {}).get('properties', {}).get('permissions', [])
        
        for permission in permissions:
            # Process regular actions
            for action in permission.get('actions', []):
                matched = self._match_actions(action, is_data_action=False)
                if matched:
                    permitted_actions.extend(matched)
                else:
                    permitted_actions.append({'name': action, 'based_on': action})

            # Process data actions
            for action in permission.get('dataActions', []):
                matched = self._match_actions(action, is_data_action=True)
                if matched:
                    permitted_data_actions.extend(matched)
                else:
                    permitted_data_actions.append({'name': action, 'based_on': action})

            # Process not actions
            for action in permission.get('notActions', []):
                matched = self._match_actions(action, is_data_action=False)
                if matched:
                    permitted_actions = [x for x in permitted_actions 
                                      if x.get('name', '').lower() not in 
                                      {m['name'].lower() for m in matched}]
                else:
                    permitted_actions.append({'name': f"Not {action}", 'based_on': f"Not {action}"})

            # Process not data actions
            for action in permission.get('notDataActions', []):
                matched = self._match_actions(action, is_data_action=True)
                if matched:
                    permitted_data_actions = [x for x in permitted_data_actions 
                                           if x.get('name', '').lower() not in 
                                           {m['name'].lower() for m in matched}]
                else:
                    permitted_data_actions.append({'name': f"Not {action}", 'based_on': f"Not {action}"})

        # Check for owner policy
        permitted_action_names = {action['name'].lower() for action in permitted_actions if 'name' in action}
        is_owner_policy = (permitted_action_names == self.all_possible_actions['regular'])

        return {
            'permitted_actions': permitted_actions,
            'permitted_data_actions': permitted_data_actions,
            'is_owner_policy': is_owner_policy
        }

def process_effective(custom_policy: Dict, services: List[Dict]) -> Dict[str, Union[List[Dict], bool]]:
    """
    Wrapper function for backward compatibility.
    """
    processor = RBACRolePermissionAnalyzer(services)
    return processor.process_effective(custom_policy)