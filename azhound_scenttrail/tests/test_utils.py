import unittest
from azhound_scenttrail.utils.analysis_utils import process_effective

class TestAzurePermissions(unittest.TestCase):
    """Test suite for Azure permission processing functionality."""

    @classmethod
    def setUpClass(cls):
        """Set up reusable test fixtures."""
        # Basic Azure service definition for testing
        cls.base_service = {
            "name": "Microsoft.Authorization",
            "operations": [
                {
                    "name": "Microsoft.Authorization/roleAssignments/read",
                    "isDataAction": False,
                    "origin": None
                },
                {
                    "name": "Microsoft.Authorization/roleAssignments/write",
                    "isDataAction": False,
                    "origin": None
                },
                {
                    "name": "Microsoft.Authorization/roleAssignments/delete",
                    "isDataAction": False,
                    "origin": None
                }
            ]
        }

        # Sample role definitions for testing
        cls.role_defs = {
            "empty": {},
            "reader": {
                "data": {
                    "properties": {
                        "permissions": [{
                            "actions": ["Microsoft.Authorization/roleAssignments/read"],
                            "notActions": []
                        }]
                    }
                }
            },
            "contributor": {
                "data": {
                    "properties": {
                        "permissions": [{
                            "actions": [
                                "Microsoft.Authorization/roleAssignments/*"
                            ],
                            "notActions": [
                                "Microsoft.Authorization/roleAssignments/write"
                            ]
                        }]
                    }
                }
            },
            "owner": {
                "data": {
                    "properties": {
                        "permissions": [{
                            "actions": ["*"],
                            "dataActions": ["*"]
                        }]
                    }
                }
            }
        }

    def test_empty_policy(self):
        """Test processing of empty policy."""
        result = process_effective(self.role_defs["empty"], [self.base_service])
        
        expected = {
            'permitted_actions': [],
            'permitted_data_actions': [],
            'is_owner_policy': False
        }
        
        self.assertEqual(result, expected)

    def test_reader_policy(self):
        """Test processing of reader policy with single read permission."""
        result = process_effective(self.role_defs["reader"], [self.base_service])
        
        expected = {
            'permitted_actions': [{
                'name': 'Microsoft.Authorization/roleAssignments/read',
                'based_on': 'Microsoft.Authorization/roleAssignments/read',
                'origin': None
            }],
            'permitted_data_actions': [],
            'is_owner_policy': False
        }
        
        self.assertEqual(result, expected)

    def test_contributor_policy(self):
        """Test processing of contributor policy with wildcard and exclusions."""
        result = process_effective(self.role_defs["contributor"], [self.base_service])
        
        expected = {
            'permitted_actions': [
                {
                    'name': 'Microsoft.Authorization/roleAssignments/read',
                    'based_on': 'Microsoft.Authorization/roleAssignments/*',
                    'origin': None
                },
                {
                    'name': 'Microsoft.Authorization/roleAssignments/delete',
                    'based_on': 'Microsoft.Authorization/roleAssignments/*',
                    'origin': None
                }
            ],
            'permitted_data_actions': [],
            'is_owner_policy': False
        }
        
        self.assertEqual(result, expected)

    def test_owner_policy(self):
        """Test processing of owner policy with full permissions."""
        services = [{
            'operations': [
                {'name': 'action1', 'isDataAction': False},
                {'name': 'action2', 'isDataAction': False},
                {'name': 'dataAction1', 'isDataAction': True},
                {'name': 'dataAction2', 'isDataAction': True}
            ]
        }]

        result = process_effective(self.role_defs["owner"], services)
        
        expected = {
            'permitted_actions': [
                {'name': 'action1', 'based_on': '*', 'origin': ''},
                {'name': 'action2', 'based_on': '*', 'origin': ''}
            ],
            'permitted_data_actions': [
                {'name': 'dataAction1', 'based_on': '*', 'origin': ''},
                {'name': 'dataAction2', 'based_on': '*', 'origin': ''}
            ],
            'is_owner_policy': True
        }
        
        self.assertEqual(result, expected)

    def test_policy_with_wildcards(self):
        """Test processing of policies with wildcard patterns."""
        policy = {
            "data": {
                "properties": {
                    "permissions": [{
                        "actions": ["Microsoft.*/read"],
                        "notActions": ["Microsoft.Auth*/write"]
                    }]
                }
            }
        }

        services = [{
            'operations': [
                {'name': 'Microsoft.Storage/read', 'isDataAction': False},
                {'name': 'Microsoft.Auth/write', 'isDataAction': False},
                {'name': 'Microsoft.Compute/read', 'isDataAction': False}
            ]
        }]

        result = process_effective(policy, services)
        
        expected = {
            'permitted_actions': [
                {'name': 'Microsoft.Storage/read', 'based_on': 'Microsoft.*/read', 'origin': ''},
                {'name': 'Microsoft.Compute/read', 'based_on': 'Microsoft.*/read', 'origin': ''}
            ],
            'permitted_data_actions': [],
            'is_owner_policy': False
        }
        
        self.assertEqual(result, expected)

if __name__ == '__main__':
    unittest.main()