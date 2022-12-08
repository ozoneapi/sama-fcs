<template>
  <div>
    <b-form-group
      label-for="scheme_name"
      label="SchemeName"
      description="OBExternalAccountIdentification4Code"
    >
      <b-form-select
        v-model="scheme_name_selector"
        :options="[
          'UK.OBIE.BBAN',
          'UK.OBIE.IBAN',
          'UK.OBIE.PAN' ,
          'UK.OBIE.Paym',
          'UK.OBIE.SortCodeAccountNumber',
          'Other'
        ]"
        :state="validSchemeName(scheme_name)"
        required
        @change="scheme_name_selector_change"
      />
    </b-form-group>
    <b-form-group
      v-if="custom_scheme_visible"
      label-for="scheme_name_other"
      label="Custom SchemeName"
      description="OBExternalAccountIdentification4Code"
    >
      <b-form-input
        v-model="scheme_name_other"
        :state="validSchemeName(scheme_name_other)"
        required
        @update="scheme_name_other_update"
      />
    </b-form-group>
  </div>
</template>

<script>
import * as _ from 'lodash';

const ACCOUNT_TYPE_INTERNATIONAL = 'International';
const ACCOUNT_TYPE_LOCAL = 'Local';
const ACCOUNT_TYPE_CBPII = 'CBPII';

export default {
  name: 'SchemeName',
  props: {
    creditorAccountType: {
      type: String,
      required: true,
    },
  },
  data() {
    let scheme_name_selector = null;
    let scheme_name_other = null;
    // removed
    return {
      scheme_name_other,
      scheme_name_selector,
      maxSchemeNameLength: 40,
    };
  },
  computed: {
    scheme_name: {
      get() {
        if (this.scheme_name_selector === 'Other' && this.isNotEmpty(this.scheme_name_other)) {
          return this.scheme_name_other;
        }

        return this.scheme_name_selector;
      },
    },
    custom_scheme_visible: {
      get() {
        return this.scheme_name_selector === 'Other';
      },
    },
  },
  methods: {
    isKnownSchemeName(schemeName) {
      return [
        'UK.OBIE.BBAN',
        'UK.OBIE.IBAN',
        'UK.OBIE.PAN',
        'UK.OBIE.Paym',
        'UK.OBIE.SortCodeAccountNumber',
      ].indexOf(schemeName) > -1;
    },
    scheme_name_other_update() {
      // removed
    },
    scheme_name_selector_change() {
      // removed
    },
    isNotEmpty(value) {
      return !_.isEmpty(value);
    },
    validSchemeName(value) {
      return this.isNotEmpty(value) && value.length <= this.maxSchemeNameLength;
    },
  },
};
</script>
