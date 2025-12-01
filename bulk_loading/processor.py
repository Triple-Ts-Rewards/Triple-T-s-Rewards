import os
from datetime import datetime
from flask import current_app
from models import db, User, Sponsor, Driver, Role, AuditLog, Organization, DriverApplication, DriverSponsorAssociation

class BulkLoadProcessor:
    """
    Processes bulk loading files for the Triple-T's Rewards system
    """
    
    def __init__(self, file_content=None, file_path=None, mode='admin'):
        """
        Initialize the bulk loading processor
        
        Args:
            file_content (str): Content of the file (for in-memory processing)
            file_path (str): Path to the bulk loading file (for file-based processing)
            mode (str): 'admin' or 'sponsor' mode
        """
        self.file_content = file_content
        self.file_path = file_path
        self.mode = mode
        self.log_file = None
        self.results = {
            'total': 0,
            'success': 0,
            'failed': 0,
            'organizations_created': 0,
            'sponsors_created': 0,
            'drivers_created': 0,
            'log_entries': []  # Store log entries for display
        }
        
        # Generate a unique session ID for this bulk load operation
        self.session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    def process_file(self):
        """
        Process the bulk loading file
        
        Returns:
            dict: Results of the processing
        """
        try:
            if self.file_content:
                # Process from memory (file content)
                lines = self.file_content.splitlines()
            else:
                # Process from file path (backwards compatibility)
                with open(self.file_path, 'r') as file:
                    lines = file.readlines()
                
            for line_num, line in enumerate(lines, 1):
                if not line.strip():
                    continue
                    
                data = line.strip().split('|')
                if not data:
                    continue
                    
                record_type = data[0].upper()
                self.results['total'] += 1
                
                try:
                    if self.mode == 'admin':
                        self._process_admin_record(record_type, data, line_num)
                    else:
                        self._process_sponsor_record(record_type, data, line_num)
                except Exception as e:
                    self.results['failed'] += 1
                    self._log_result(line_num, record_type, 'Failed', str(data), f'Exception: {str(e)}')
                    db.session.rollback()
                    
            # Log the completion of bulk load operation
            self._log_audit_event(0, 'bulk_load_completed', 
                                 f'Bulk load session {self.session_id} completed. '
                                 f'Total: {self.results["total"]}, Success: {self.results["success"]}, '
                                 f'Failed: {self.results["failed"]}, Organizations: {self.results["organizations_created"]}, '
                                 f'Sponsors: {self.results["sponsors_created"]}, Drivers: {self.results["drivers_created"]}')
                
            return self.results
        except Exception as e:
            # Log the error in the audit log
            self._log_audit_event(0, 'bulk_load_error', 
                                 f'Bulk load session {self.session_id} failed with error: {str(e)}')
            raise e
    
    def _process_admin_record(self, record_type, data, line_num):
        """
        Process a record in admin mode
        
        Args:
            record_type (str): Type of record ('O', 'D', 'S')
            data (list): Record data
            line_num (int): Line number in the file
        """
        if record_type == 'O':
            # Create organization
            if len(data) >= 2:
                org_name = data[1]
                self._create_organization(org_name, line_num)
            else:
                self.results['failed'] += 1
                self._log_result(line_num, record_type, 'Failed', str(data), 'Insufficient data for organization record')
        
        elif record_type == 'S':
            # Create sponsor
            if len(data) >= 5:
                org_name, first_name, last_name, email = data[1], data[2], data[3], data[4]
                self._create_sponsor(org_name, first_name, last_name, email, line_num)
            else:
                self.results['failed'] += 1
                self._log_result(line_num, record_type, 'Failed', str(data), 'Insufficient data for sponsor record. Format: S|Organization|FirstName|LastName|Email')
                
        elif record_type == 'D':
            # Create driver
            if len(data) >= 5:  # Need 5 fields: D|org|first|last|email
                org_name, first_name, last_name, email = data[1], data[2], data[3], data[4]
                self._create_driver(org_name, first_name, last_name, email, line_num)
            else:
                self.results['failed'] += 1
                self._log_result(line_num, record_type, 'Failed', str(data), 'Insufficient data for driver record. Format: D|Organization|FirstName|LastName|Email')
                
        else:
            self.results['failed'] += 1
            self._log_result(line_num, record_type, 'Failed', str(data), f'Unknown record type: {record_type}')
    
    def _process_sponsor_record(self, record_type, data, line_num):
        """
        Process a record in sponsor mode
        Sponsors can only create drivers (D) and other sponsors (S)
        They cannot create organizations (O)
        
        Args:
            record_type (str): Type of record ('D' or 'S')
            data (list): Record data
            line_num (int): Line number in the file
        """
        if record_type == 'O':
            # Sponsors cannot create organizations
            self.results['failed'] += 1
            self._log_result(line_num, record_type, 'Failed', str(data), 
                           'Access denied: Sponsors cannot create organizations. Only administrators can create organizations.')
            return
            
        elif record_type == 'S':
            # Create sponsor - sponsors can create other sponsors in their own organization
            # Format MUST be: S||FirstName|LastName|Email (with empty org field)
            if len(data) >= 5 and data[1] == '':
                # S||FirstName|LastName|Email (correct format with empty org field)
                first_name, last_name, email = data[2], data[3], data[4]
                self._create_sponsor_by_sponsor(first_name, last_name, email, line_num)
            else:
                self.results['failed'] += 1
                if len(data) < 5:
                    self._log_result(line_num, record_type, 'Failed', str(data), 
                                   'Insufficient data for sponsor record. Format required: S||FirstName|LastName|Email')
                else:
                    self._log_result(line_num, record_type, 'Failed', str(data), 
                                   'Invalid format for sponsor record. Format required: S||FirstName|LastName|Email (note the two pipes)')
                
        elif record_type == 'D':
            # Create driver - sponsors can create drivers for their organization  
            # Format MUST be: D||FirstName|LastName|Email (with empty org field)
            if len(data) >= 5 and data[1] == '':
                # D||FirstName|LastName|Email (correct format with empty org field)
                first_name, last_name, email = data[2], data[3], data[4]
                self._create_driver_by_sponsor(first_name, last_name, email, line_num)
            else:
                self.results['failed'] += 1
                if len(data) < 5:
                    self._log_result(line_num, record_type, 'Failed', str(data), 
                                   'Insufficient data for driver record. Format required: D||FirstName|LastName|Email')
                else:
                    self._log_result(line_num, record_type, 'Failed', str(data), 
                                   'Invalid format for driver record. Format required: D||FirstName|LastName|Email (note the two pipes)')
                
        else:
            self.results['failed'] += 1
            self._log_result(line_num, record_type, 'Failed', str(data), f'Unknown record type: {record_type}')
    
    def _create_sponsor(self, org_name, first_name, last_name, email, line_num):
        """
        Create a new sponsor user and organization
        
        Args:
            org_name (str): Organization name
            first_name (str): First name
            last_name (str): Last name
            email (str): Email address
            line_num (int): Line number in the file
        """
        # Check if email already exists
        existing_user = User.query.filter_by(EMAIL=email).first()
        if existing_user:
            self.results['failed'] += 1
            self._log_result(line_num, 'S', 'Failed', f'{first_name} {last_name} ({email})', f'Email already exists: {email}')
            return
        
        # Check if organization exists in Organizations table
        existing_org = Organization.query.filter_by(ORG_NAME=org_name).first()
        if not existing_org:
            # Auto-create the organization if it doesn't exist
            try:
                new_org = Organization(
                    ORG_NAME=org_name,
                    CREATED_AT=datetime.now(),
                    STATUS='Approved'
                )
                db.session.add(new_org)
                db.session.commit()
                existing_org = new_org
                self.results['organizations_created'] += 1
                self._log_audit_event(0, 'organization_auto_created_via_bulk_load', f'Auto-created organization: {org_name} (ID: {new_org.ORG_ID}) for sponsor creation')
            except Exception as e:
                db.session.rollback()
                self.results['failed'] += 1
                self._log_result(line_num, 'S', 'Failed', f'{first_name} {last_name} ({email})', f'Could not create organization "{org_name}": {str(e)}')
                return
            
        # Multiple sponsors per organization are now allowed - no restriction needed
        
        try:
            # Generate a unique username
            username = self._generate_unique_username(first_name, last_name)
            
            # Create the user (let USER_CODE auto-increment)
            new_user = User(
                USERNAME=username,
                USER_TYPE=Role.SPONSOR,
                FNAME=first_name,
                LNAME=last_name,
                EMAIL=email,
                CREATED_AT=datetime.now(),
                wants_point_notifications=True,
                wants_order_notifications=True,
                wants_security_notifications=True,
                IS_ACTIVE=1,
                FAILED_ATTEMPTS=0,
                IS_LOCKED_OUT=0
            )
            
            # Generate a random password
            password = new_user.admin_set_new_pass()
            
            db.session.add(new_user)
            db.session.commit()  # Commit the user first to get the auto-generated USER_CODE
            
            # Create the sponsor
            new_sponsor = Sponsor(
                USER_CODE=new_user.USER_CODE,
                ORG_ID=existing_org.ORG_ID
            )
            
            db.session.add(new_sponsor)
            db.session.commit()
            
            # Log the event
            self._log_audit_event(new_user.USER_CODE, 'sponsor_created_via_bulk_load', f'Created sponsor: {first_name} {last_name}, Org: {org_name}')
            
            self.results['success'] += 1
            self.results['sponsors_created'] += 1
            self._log_result(line_num, 'S', 'Success', f'{first_name} {last_name} ({email})', f'Username: {username}, Password: {password}')
        except Exception as e:
            db.session.rollback()
            self.results['failed'] += 1
            self._log_result(line_num, 'S', 'Failed', f'{first_name} {last_name} ({email})', f'Database error: {str(e)}')
            raise e
    
    def _create_driver(self, org_name, first_name, last_name, email, line_num):
        """
        Create a new driver user
        
        Args:
            org_name (str): Organization name (sponsor org)
            first_name (str): First name
            last_name (str): Last name
            email (str): Email address
            line_num (int): Line number in the file
        """
        # Check if email already exists
        existing_user = User.query.filter_by(EMAIL=email).first()
        if existing_user:
            self.results['failed'] += 1
            self._log_result(line_num, 'D', 'Failed', f'{first_name} {last_name} ({email})', f'Email already exists: {email}')
            return
            
        # Check if the organization exists
        existing_org = Organization.query.filter_by(ORG_NAME=org_name).first()
        if not existing_org:
            # Auto-create the organization if it doesn't exist
            try:
                new_org = Organization(
                    ORG_NAME=org_name,
                    CREATED_AT=datetime.now(),
                    STATUS='Approved'
                )
                db.session.add(new_org)
                db.session.commit()
                existing_org = new_org
                self.results['organizations_created'] += 1
                self._log_audit_event(0, 'organization_auto_created_via_bulk_load', f'Auto-created organization: {org_name} (ID: {new_org.ORG_ID}) for driver creation')
            except Exception as e:
                db.session.rollback()
                self.results['failed'] += 1
                self._log_result(line_num, 'D', 'Failed', f'{first_name} {last_name} ({email})', f'Could not create organization "{org_name}": {str(e)}')
                return
        try:
            # Generate a unique username
            username = self._generate_unique_username(first_name, last_name)
            
            # Create the user (let USER_CODE auto-increment)
            new_user = User(
                USERNAME=username,
                USER_TYPE=Role.DRIVER,
                FNAME=first_name,
                LNAME=last_name,
                EMAIL=email,
                CREATED_AT=datetime.now(),
                wants_point_notifications=True,
                wants_order_notifications=True,
                wants_security_notifications=True,
                IS_ACTIVE=1,
                FAILED_ATTEMPTS=0,
                IS_LOCKED_OUT=0
            )
            
            # Generate a random password
            password = new_user.admin_set_new_pass()
            
            db.session.add(new_user)
            db.session.commit()  # Commit the user first to get the auto-generated USER_CODE
            
            # Create the driver (license number will be added separately later)
            new_driver = Driver(
                DRIVER_ID=new_user.USER_CODE,
                LICENSE_NUMBER="PENDING"  # Placeholder - to be updated later
            )
            
            db.session.add(new_driver)
            db.session.commit()
            
            # Create the DriverSponsorAssociation to link driver with organization
            driver_org_association = DriverSponsorAssociation(
                driver_id=new_user.USER_CODE,
                ORG_ID=existing_org.ORG_ID,
                points=0
            )
            
            db.session.add(driver_org_association)
            db.session.commit()
            
            # Log the event
            self._log_audit_event(new_user.USER_CODE, 'driver_created_via_bulk_load', 
                                 f'Created driver: {first_name} {last_name} for organization: {org_name} (ORG_ID: {existing_org.ORG_ID})')
            
            self.results['success'] += 1
            self.results['drivers_created'] += 1
            self._log_result(line_num, 'D', 'Success', f'{first_name} {last_name} ({email})', f'Username: {username}, Password: {password}, Organization: {org_name}')
        except Exception as e:
            db.session.rollback()
            self.results['failed'] += 1
            self._log_result(line_num, 'D', 'Failed', f'{first_name} {last_name} ({email})', f'Database error: {str(e)}')
            raise e
    
    def _create_organization(self, org_name, line_num):
        """
        Create an organization record in the database
        
        Args:
            org_name (str): Organization name
            line_num (int): Line number in the file
        """
        # Check if organization already exists
        existing_org = Organization.query.filter_by(ORG_NAME=org_name).first()
        if existing_org:
            self.results['success'] += 1  # Count as success, not failure
            self._log_result(line_num, 'O', 'Success', org_name, f'Organization already exists: {org_name} (ID: {existing_org.ORG_ID}) - Skipping creation')
            return
        
        try:
            # Create new organization
            new_org = Organization(
                ORG_NAME=org_name,
                CREATED_AT=datetime.now(),
                STATUS='Approved'
            )
            
            db.session.add(new_org)
            db.session.commit()
            
            self.results['success'] += 1
            self.results['organizations_created'] += 1
            self._log_result(line_num, 'O', 'Success', org_name, f'Organization "{org_name}" created successfully (ID: {new_org.ORG_ID})')
            
            # Log the event
            self._log_audit_event(0, 'organization_created_via_bulk_load', f'Created organization: {org_name} (ID: {new_org.ORG_ID})')
            
        except Exception as e:
            db.session.rollback()
            self.results['failed'] += 1
            self._log_result(line_num, 'O', 'Failed', org_name, f'Database error creating organization: {str(e)}')
            raise e
    
    def _generate_unique_username(self, first_name, last_name):
        """
        Generate a unique username based on first and last name
        
        Args:
            first_name (str): First name
            last_name (str): Last name
            
        Returns:
            str: Unique username
        """
        import random
        
        # Create base username (first initial + last name, all lowercase)
        base_username = (first_name[0] + last_name).lower()
        
        # Remove non-alphanumeric characters
        base_username = ''.join(c for c in base_username if c.isalnum())
        
        # Check if username exists
        username = base_username
        counter = 1
        
        while User.query.filter_by(USERNAME=username).first():
            # If username exists, add a number to the end
            username = f"{base_username}{counter}"
            counter += 1
            
            # If we've tried too many times, add some randomness
            if counter > 100:
                username = f"{base_username}{random.randint(1000, 9999)}"
                if not User.query.filter_by(USERNAME=username).first():
                    break
        
        return username
    
    def _create_sponsor_by_sponsor(self, first_name, last_name, email, line_num):
        """
        Create a new sponsor user by another sponsor (same organization)
        
        Args:
            first_name (str): First name
            last_name (str): Last name
            email (str): Email address
            line_num (int): Line number in the file
        """
        from flask_login import current_user
        
        # Get the current sponsor's organization
        current_sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
        if not current_sponsor:
            self.results['failed'] += 1
            self._log_result(line_num, 'S', 'Failed', f'{first_name} {last_name} ({email})', 
                           'Current user is not a valid sponsor')
            return
        
        # Get the organization from the sponsor's ORG_ID
        organization = Organization.query.filter_by(ORG_ID=current_sponsor.ORG_ID).first()
        if not organization:
            self.results['failed'] += 1
            self._log_result(line_num, 'S', 'Failed', f'{first_name} {last_name} ({email})', 
                           f'Organization not found for sponsor ORG_ID: {current_sponsor.ORG_ID}')
            return
            
        org_name = organization.ORG_NAME
        
        # Check if email already exists
        existing_user = User.query.filter_by(EMAIL=email).first()
        if existing_user:
            self.results['failed'] += 1
            self._log_result(line_num, 'S', 'Failed', f'{first_name} {last_name} ({email})', 
                           f'Email already exists: {email}')
            return
            
        # Multiple sponsors per organization are now allowed - no need to check for existing sponsors
        
        try:
            # Generate a unique username
            username = self._generate_unique_username(first_name, last_name)
            
            # Create the user
            new_user = User(
                USERNAME=username,
                USER_TYPE=Role.SPONSOR,
                FNAME=first_name,
                LNAME=last_name,
                EMAIL=email,
                CREATED_AT=datetime.now(),
                wants_point_notifications=True,
                wants_order_notifications=True,
                wants_security_notifications=True,
                IS_ACTIVE=1,
                FAILED_ATTEMPTS=0,
                IS_LOCKED_OUT=0
            )
            
            # Generate a random password
            password = new_user.admin_set_new_pass()
            
            db.session.add(new_user)
            db.session.commit()
            
            # Create the sponsor
            new_sponsor = Sponsor(
                USER_CODE=new_user.USER_CODE,
                ORG_ID=organization.ORG_ID
            )
            
            db.session.add(new_sponsor)
            db.session.commit()
            
            # Log the event
            self._log_audit_event(new_user.USER_CODE, 'sponsor_created_by_sponsor', 
                                 f'Sponsor {current_user.USERNAME} created new sponsor: {first_name} {last_name}, Org: {org_name}')
            
            self.results['success'] += 1
            self.results['sponsors_created'] += 1
            self._log_result(line_num, 'S', 'Success', f'{first_name} {last_name} ({email})', 
                           f'Username: {username}, Password: {password}')
        except Exception as e:
            db.session.rollback()
            self.results['failed'] += 1
            self._log_result(line_num, 'S', 'Failed', f'{first_name} {last_name} ({email})', 
                           f'Database error: {str(e)}')
            raise e
    
    def _create_driver_by_sponsor(self, first_name, last_name, email, line_num):
        """
        Create a new driver user by a sponsor
        
        Args:
            first_name (str): First name
            last_name (str): Last name
            email (str): Email address
            line_num (int): Line number in the file
        """
        from flask_login import current_user
        
        # Get the current sponsor's organization
        current_sponsor = Sponsor.query.filter_by(USER_CODE=current_user.USER_CODE).first()
        if not current_sponsor:
            self.results['failed'] += 1
            self._log_result(line_num, 'D', 'Failed', f'{first_name} {last_name} ({email})', 
                           'Current user is not a valid sponsor')
            return
            
        # Get the organization from the sponsor's ORG_ID
        organization = Organization.query.filter_by(ORG_ID=current_sponsor.ORG_ID).first()
        if not organization:
            self.results['failed'] += 1
            self._log_result(line_num, 'D', 'Failed', f'{first_name} {last_name} ({email})', 
                           f'Organization not found for sponsor ORG_ID: {current_sponsor.ORG_ID}')
            return
        
        org_name = organization.ORG_NAME
        
        # Check if email already exists
        existing_user = User.query.filter_by(EMAIL=email).first()
        if existing_user:
            self.results['failed'] += 1
            self._log_result(line_num, 'D', 'Failed', f'{first_name} {last_name} ({email})', 
                           f'Email already exists: {email}')
            return
            
        try:
            # Generate a unique username
            username = self._generate_unique_username(first_name, last_name)
            
            # Create the user
            new_user = User(
                USERNAME=username,
                USER_TYPE=Role.DRIVER,
                FNAME=first_name,
                LNAME=last_name,
                EMAIL=email,
                CREATED_AT=datetime.now(),
                wants_point_notifications=True,
                wants_order_notifications=True,
                wants_security_notifications=True,
                IS_ACTIVE=1,
                FAILED_ATTEMPTS=0,
                IS_LOCKED_OUT=0
            )
            
            # Generate a random password
            password = new_user.admin_set_new_pass()
            
            db.session.add(new_user)
            db.session.commit()
            
            # Create the driver
            new_driver = Driver(
                DRIVER_ID=new_user.USER_CODE,
                LICENSE_NUMBER="PENDING"  # Placeholder - to be updated later
            )
            
            db.session.add(new_driver)
            db.session.commit()
            
            # Automatically create and accept a DriverApplication to connect the driver to the sponsor's organization
            # We already have the organization from the earlier lookup
            driver_application = DriverApplication(
                DRIVER_ID=new_user.USER_CODE,
                ORG_ID=organization.ORG_ID,  # Link to the sponsor's organization
                STATUS="Accepted",  # Automatically accept since sponsor created the driver
                REASON="Created via bulk loading by sponsor",
                APPLIED_AT=datetime.utcnow(),
                RESPONDED_AT=datetime.utcnow(),
                SPONSOR_RESPONSIBLE_ID=current_user.USER_CODE
            )
            
            db.session.add(driver_application)
            db.session.commit()
            
            # Create the DriverSponsorAssociation to link driver with organization
            driver_org_association = DriverSponsorAssociation(
                driver_id=new_user.USER_CODE,
                ORG_ID=organization.ORG_ID,
                points=0
            )
            
            db.session.add(driver_org_association)
            db.session.commit()
            
            # Log the event
            self._log_audit_event(new_user.USER_CODE, 'driver_created_by_sponsor', 
                                 f'Sponsor {current_user.USERNAME} created driver: {first_name} {last_name} for organization: {org_name} (ORG_ID: {organization.ORG_ID})')
            
            self.results['success'] += 1
            self.results['drivers_created'] += 1
            self._log_result(line_num, 'D', 'Success', f'{first_name} {last_name} ({email})', 
                           f'Username: {username}, Password: {password}, Organization: {org_name}')
        except Exception as e:
            db.session.rollback()
            self.results['failed'] += 1
            self._log_result(line_num, 'D', 'Failed', f'{first_name} {last_name} ({email})', 
                           f'Database error: {str(e)}')
            raise e
    
    def _log_result(self, line_num, record_type, status, details, message):
        """
        Log a result to the audit log database
        
        Args:
            line_num (int): Line number in the file
            record_type (str): Type of record
            status (str): 'Success' or 'Failed'
            details (str): Record details
            message (str): Additional message
        """
        # Create audit log entry
        event_type = f'bulk_load_{record_type.lower()}_{status.lower()}'
        log_details = f'Session: {self.session_id}, Line: {line_num}, Type: {record_type}, Details: {details}, Message: {message}'
        
        self._log_audit_event(0, event_type, log_details)
        
        # Also store in results for display purposes
        log_entry = {
            'line_num': line_num,
            'record_type': record_type,
            'status': status,
            'details': details,
            'message': message
        }
        self.results['log_entries'].append(log_entry)
    
    def _log_audit_event(self, user_id, event_type, details):
        """
        Log an audit event to the database
        
        Args:
            user_id (int): User ID
            event_type (str): Type of event
            details (str): Event details
        """
        try:
            log_entry = AuditLog(
                EVENT_TYPE=event_type,
                DETAILS=details,
                CREATED_AT=datetime.now()
            )
            db.session.add(log_entry)
            db.session.commit()  # Commit immediately for audit logging
        except Exception as e:
            # If audit logging fails, we still want the main process to continue
            db.session.rollback()
            print(f"Warning: Failed to log audit event: {str(e)}")