"""
Defensive GUI Programming Utilities

Provides defensive programming patterns and validation utilities to prevent
common GUI component initialization issues and runtime errors.

This module helps enforce proper attribute initialization and provides
validation patterns to catch issues early in development.
"""

import tkinter as tk
from typing import Any, Dict, List, Optional, Type
import inspect
import warnings


class AttributeValidator:
    """
    Validates that required attributes are properly initialized in GUI classes.
    
    This validator can be used in __init__ methods to ensure all required
    attributes are initialized, helping prevent AttributeError exceptions.
    """
    
    @staticmethod
    def validate_attributes(instance: Any, required_attrs: List[str], 
                          class_name: Optional[str] = None) -> bool:
        """
        Validate that all required attributes exist on an instance.
        
        Args:
            instance: Object instance to validate
            required_attrs: List of required attribute names
            class_name: Optional class name for error messages
            
        Returns:
            True if all attributes exist, False otherwise
            
        Raises:
            AttributeError: If any required attributes are missing (in strict mode)
        """
        class_name = class_name or instance.__class__.__name__
        missing_attrs = []
        
        for attr in required_attrs:
            if not hasattr(instance, attr):
                missing_attrs.append(attr)
        
        if missing_attrs:
            error_msg = (f"{class_name} missing required attributes: {missing_attrs}. "
                        f"This could cause AttributeError at runtime.")
            
            # For now, just warn - in the future this could be made stricter
            warnings.warn(error_msg, UserWarning, stacklevel=2)
            return False
        
        return True
    
    @staticmethod 
    def validate_stringvars(instance: Any, stringvar_attrs: List[str],
                           class_name: Optional[str] = None) -> bool:
        """
        Validate that StringVar attributes are properly initialized.
        
        Args:
            instance: Object instance to validate
            stringvar_attrs: List of attribute names that should be StringVars
            class_name: Optional class name for error messages
            
        Returns:
            True if all StringVar attributes are valid, False otherwise
        """
        class_name = class_name or instance.__class__.__name__
        invalid_attrs = []
        
        for attr in stringvar_attrs:
            if hasattr(instance, attr):
                attr_obj = getattr(instance, attr)
                if not isinstance(attr_obj, tk.StringVar):
                    invalid_attrs.append(f"{attr} (type: {type(attr_obj).__name__})")
            else:
                invalid_attrs.append(f"{attr} (missing)")
        
        if invalid_attrs:
            error_msg = (f"{class_name} has invalid StringVar attributes: {invalid_attrs}")
            warnings.warn(error_msg, UserWarning, stacklevel=2)
            return False
        
        return True


class SafeGUIBase:
    """
    Base class providing defensive programming patterns for GUI components.
    
    This class provides common defensive patterns that can be inherited
    or used as a mixin to add safety checks to GUI components.
    """
    
    def __init__(self):
        """Initialize safe GUI base."""
        self._initialization_complete = False
        self._required_attributes = []
        self._stringvar_attributes = []
    
    def _set_required_attributes(self, required_attrs: List[str]) -> None:
        """Set list of required attributes for validation."""
        self._required_attributes = required_attrs
    
    def _set_stringvar_attributes(self, stringvar_attrs: List[str]) -> None:
        """Set list of StringVar attributes for validation."""
        self._stringvar_attributes = stringvar_attrs
    
    def _validate_initialization(self) -> bool:
        """
        Validate that the instance is properly initialized.
        
        Returns:
            True if validation passes, False otherwise
        """
        if not self._initialization_complete:
            warnings.warn(f"{self.__class__.__name__} validation called before "
                         f"initialization complete", UserWarning)
            return False
        
        # Validate required attributes
        if self._required_attributes:
            if not AttributeValidator.validate_attributes(
                self, self._required_attributes, self.__class__.__name__):
                return False
        
        # Validate StringVar attributes
        if self._stringvar_attributes:
            if not AttributeValidator.validate_stringvars(
                self, self._stringvar_attributes, self.__class__.__name__):
                return False
        
        return True
    
    def _mark_initialization_complete(self) -> None:
        """Mark initialization as complete and run validation."""
        self._initialization_complete = True
        self._validate_initialization()
    
    def _safe_getattr(self, attr_name: str, default: Any = None) -> Any:
        """
        Safely get an attribute with a default value.
        
        Args:
            attr_name: Name of attribute to get
            default: Default value if attribute doesn't exist
            
        Returns:
            Attribute value or default
        """
        return getattr(self, attr_name, default)
    
    def _safe_widget_operation(self, widget: Optional[tk.Widget], 
                             operation: str, *args, **kwargs) -> bool:
        """
        Safely perform an operation on a widget.
        
        Args:
            widget: Widget to operate on (may be None)
            operation: Name of operation to perform
            *args, **kwargs: Arguments for the operation
            
        Returns:
            True if operation succeeded, False otherwise
        """
        if widget is None:
            warnings.warn(f"Attempted {operation} on None widget in "
                         f"{self.__class__.__name__}", UserWarning)
            return False
        
        try:
            if hasattr(widget, operation):
                method = getattr(widget, operation)
                method(*args, **kwargs)
                return True
            else:
                warnings.warn(f"Widget {type(widget).__name__} has no method "
                             f"{operation}", UserWarning)
                return False
        except Exception as e:
            warnings.warn(f"Widget operation {operation} failed: {e}", UserWarning)
            return False


def create_safe_stringvar(default_value: str = "") -> tk.StringVar:
    """
    Create a StringVar with a default value.
    
    Args:
        default_value: Default value for the StringVar
        
    Returns:
        Initialized StringVar
    """
    var = tk.StringVar()
    var.set(default_value)
    return var


def initialize_gui_attributes(instance: Any, attribute_spec: Dict[str, Any]) -> None:
    """
    Initialize GUI attributes from a specification dictionary.
    
    Args:
        instance: Object instance to initialize
        attribute_spec: Dictionary mapping attribute names to default values
                       Special values:
                       - 'StringVar:value' - Creates StringVar with default value
                       - 'StringVar' - Creates StringVar with empty string
                       - None - Sets attribute to None
    """
    for attr_name, default_value in attribute_spec.items():
        if isinstance(default_value, str) and default_value.startswith('StringVar'):
            # Handle StringVar initialization
            if ':' in default_value:
                _, default_val = default_value.split(':', 1)
                setattr(instance, attr_name, create_safe_stringvar(default_val))
            else:
                setattr(instance, attr_name, create_safe_stringvar())
        else:
            # Handle regular attribute initialization
            setattr(instance, attr_name, default_value)


# Example usage pattern for GUI classes:
"""
class MyGUIClass(SafeGUIBase):
    def __init__(self, parent):
        super().__init__()
        
        self.parent = parent
        
        # Define required attributes
        self._set_required_attributes([
            'search_text', 'status_label', 'tree_widget'
        ])
        
        self._set_stringvar_attributes([
            'search_text', 'filter_text'
        ])
        
        # Initialize attributes using defensive pattern
        initialize_gui_attributes(self, {
            'search_text': 'StringVar:',
            'filter_text': 'StringVar:All',
            'status_label': None,
            'tree_widget': None,
            'progress_bar': None
        })
        
        # Create GUI
        self._build_ui()
        
        # Mark initialization complete (triggers validation)
        self._mark_initialization_complete()
    
    def _build_ui(self):
        # Build actual UI components
        self.status_label = tk.Label(self.parent, text="Ready")
        # ... etc
    
    def update_status(self, message):
        # Use safe widget operation
        self._safe_widget_operation(self.status_label, 'config', text=message)
"""