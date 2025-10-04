from app import app, Vaccine

with app.app_context():
    vaccines = Vaccine.query.all()
    if not vaccines:
        print("No vaccines found in database!")
    else:
        for v in vaccines:
            print(f"{v.name} - {v.description}")
            for dose in v.doses:
                print(f"  Dose {dose.dose_number}, Age: {dose.recommended_age_months} months")
