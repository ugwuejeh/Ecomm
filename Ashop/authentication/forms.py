from django import forms
from .models import Registration

class VendorApplyForm(forms.ModelForm):
    class Meta:
        model = Registration
        fields = ['business_name', 'registration_no', 'registering_body', 'location', 'business_description', 'website_url']


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # self.fields['business_name'].widget.attrs['placeholder'] = 'Enter business name'
        # self.fields['registration_no'].widget.attrs['placeholder'] = 'Enter registration number'
        # self.fields['registering_body'].widget.attrs['placeholder'] = 'Enter registering body'
        # self.fields['location'].widget.attrs['placeholder'] = 'Enter location'
        # self.fields['business_description'].widget.attrs['placeholder'] = 'Enter business description'
        self.fields['website_url'].widget.attrs['placeholder'] = 'Enter website URL (optional)'

        for field in self.fields.values():
            field.widget.attrs['style'] = 'border:1px solid black;'

        # Set required attribute for all fields except website_url
        for field_name, field in self.fields.items():
            if field_name != 'website_url':
                field.required = True  