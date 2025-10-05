# update_due_date.py
# Script to update a vaccine due_date for a child for reminder testing

from app import db, VaccinationRecord, Child, app
from datetime import date, timedelta

# --- CONFIGURE THESE VALUES ---
CHILD_NAME = "Femin"  # Change to your test child's name
NEW_DUE_DATE = date.today() + timedelta(days=7)  # Set to 7 days from today

with app.app_context():
    child = Child.query.filter_by(name=CHILD_NAME).first()
    # ...existing code...
    if not child:
        print(f"No child found with name: {CHILD_NAME}")
    else:
        record = VaccinationRecord.query.filter_by(child_id=child.id, date_taken=None).first()
        if not record:
            print(f"No upcoming vaccine record found for child: {CHILD_NAME}")
        else:
            print(f"Updating due_date for vaccine {record.vaccine.name} (dose {record.dose_number}) to {NEW_DUE_DATE}")
            record.due_date = NEW_DUE_DATE
            db.session.commit()
            print("Due date updated successfully!")
