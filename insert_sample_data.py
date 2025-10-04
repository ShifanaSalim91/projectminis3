from app import db, app, Vaccine, VaccineDose

with app.app_context():
    # ---------- Sample Vaccines ----------
    bcg = Vaccine(name="BCG", description="Prevents tuberculosis")
    opv = Vaccine(name="OPV", description="Oral Polio Vaccine")
    mmr = Vaccine(name="MMR", description="Measles, Mumps, Rubella Vaccine")

    db.session.add_all([bcg, opv, mmr])
    db.session.commit()  # Save to DB to get IDs

    # ---------- Sample Vaccine Doses ----------
    bcg_dose1 = VaccineDose(vaccine_id=bcg.id, dose_number=1, recommended_age_months=0)
    opv_dose1 = VaccineDose(vaccine_id=opv.id, dose_number=1, recommended_age_months=0)
    opv_dose2 = VaccineDose(vaccine_id=opv.id, dose_number=2, recommended_age_months=6)
    opv_dose3 = VaccineDose(vaccine_id=opv.id, dose_number=3, recommended_age_months=10)
    mmr_dose1 = VaccineDose(vaccine_id=mmr.id, dose_number=1, recommended_age_months=9)
    mmr_dose2 = VaccineDose(vaccine_id=mmr.id, dose_number=2, recommended_age_months=15)

    db.session.add_all([bcg_dose1, opv_dose1, opv_dose2, opv_dose3, mmr_dose1, mmr_dose2])
    db.session.commit()

    print("Sample vaccines and doses added successfully!")
