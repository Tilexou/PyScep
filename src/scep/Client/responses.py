from cryptography.hazmat.primitives.asymmetric import padding

from .enums import CACaps, PKIStatus


class Capabilities:
    def __init__(self, caps):
        self.caps = caps

    def contains(self, capability):
        return self.caps.__contains__(capability)

    def supports(self, capability: str) -> bool:
        for cap in self.caps:
            if capability.lower() == cap.value.lower():
                return True

        return False

    def is_post_supported(self):
        return self.contains(CACaps.POSTPKIOperation)

    def is_rollover_supported(self):
        return self.contains(CACaps.GetNextCACert)

    def is_renewal_supported(self):
        return self.contains(CACaps.Renewal)

    def is_update_supported(self):
        return self.contains(CACaps.Update)

    def strongest_cipher(self):
        if self.contains(CACaps.AES):
            if self.contains(CACaps.SHA256):
                return 'aes256'
            else:
                return 'aes128'
        else:
            return '3des'

    def strongest_message_digest(self):
        if self.contains(CACaps.SHA512):
            return 'sha512'
        elif self.contains(CACaps.SHA256):
            return 'sha256'
        elif self.contains(CACaps.SHA1):
            return 'sha1'
        else:
            return 'md5'

    def strongest_signature_algorithm(self):
        if self.contains(CACaps.SHA512):
            return 'sha512'
        elif self.contains(CACaps.SHA256):
            return 'sha256'
        elif self.contains(CACaps.SHA1):
            return 'sha1'
        else:
            return 'md5'


class CACertificates:
    def __init__(self, certificates):
        self._certificates = certificates

        # recipient
        #   RA Certificate with Key Encipherment (RA Encryption Certificate)
        #   Used to encrypt the SCEP message content (PKCS#7 SignedData, which contains the PKCS#10 CSR and the challenge password)
        #   Dedicated certificate in Microsoft NDES implementation, can be the CA itself in others
        # signer
        #   RA Certificate with Digital Signature (RA Signing Certificate)
        #   Used to verify the SCEP server's response (PKCS#7 SignedData) (issued certificate, pending response, etc.)
        #   Dedicated certificate in Microsoft NDES implementation, can be the CA itself in others
        # issuer
        #   CA certificate (Intermediate if provided, Root otherwise) with Certificate Sign and/or CRL Sign
        #   Used to verify the RA certificates and any issued certificate
        # chain
        #   CA certificate(s) (Intermediate(s) if provided and Root) with Certificate Sign and/or CRL Sign
        #   Contains the issuer
        self._recipient = self.__recipient()
        self._signer = self.__signer()
        self._issuer = self.__issuer()
        self._chain = self.__chain()

    @property
    def certificates(self):
        return self._certificates

    def verify(self):
        assert self.issuer is not None
        assert self.signer is not None
        assert self.recipient is not None

        try:
            if self.issuer != self.recipient:
                self.issuer.to_crypto_certificate().public_key().verify(
                    self.recipient.to_crypto_certificate().signature,
                    self.recipient.to_crypto_certificate().tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    self.recipient.to_crypto_certificate().signature_hash_algorithm
                )
        except Exception as e:
            raise Exception('RA is not issued by CA')

        try:
            if self.issuer != self.signer:
                self.issuer.to_crypto_certificate().public_key().verify(
                    self.signer.to_crypto_certificate().signature,
                    self.signer.to_crypto_certificate().tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    self.signer.to_crypto_certificate().signature_hash_algorithm
                )
        except Exception as e:
            raise Exception('RA is not issued by CA')

    @property
    def signer(self):
        return self._signer

    def __signer(self):
        required = set(['digital_signature'])
        not_required = set()
        digital_sign = self._filter(required_key_usage=required, not_required_key_usage=not_required, ca_only=False)
        if len(digital_sign) > 0:
            return digital_sign[0]

        ca = self._filter(required_key_usage=set(), not_required_key_usage=set(), ca_only=True)
        if len(ca) > 0:
            return ca[0]

        return None

    @property
    def issuer(self):
        return self._issuer

    def __issuer(self):
        ca = self._filter(required_key_usage=set(), not_required_key_usage=set(), ca_only=True)
        expected = self.recipient.issuer
        for cert in ca:
            if cert.subject == expected:
                return cert

        if ca[0] == self.recipient:
            return cert

        return None

    @property
    def recipient(self):
        return self._recipient

    def __recipient(self):
        required = set(['key_encipherment'])
        not_required = set(['digital_signature', 'non_repudiation', 'data_encipherment'])
        key_enc = self._filter(required_key_usage=required, not_required_key_usage=not_required, ca_only=False)
        if len(key_enc) > 0:
            return key_enc[0]

        required = set(['data_encipherment'])
        not_required = set(['digital_signature', 'non_repudiation', 'key_encipherment'])
        data_enc = self._filter(required_key_usage=required, not_required_key_usage=not_required, ca_only=False)
        if len(data_enc) > 0:
            return data_enc[0]

        ca = self._filter(required_key_usage=set(), not_required_key_usage=set(), ca_only=True)
        if len(ca) > 0:
            return ca[0]

        return None

    @property
    def chain(self):
        return self._chain

    def __chain(self):
        cas = self._filter(required_key_usage=set(), not_required_key_usage=set(), ca_only=True)

        return CACertificates.sort_cas(cas)

    def _filter(self, required_key_usage, not_required_key_usage, ca_only=False):
        matching_certificates = list()
        for cert in self._certificates:
            if bool(cert.is_ca) != ca_only:
                continue

            # Having the key_usage field can be optional.
            # ref: https://security.stackexchange.com/questions/68491/recommended-key-usage-for-a-client-certificate
            # ref: https://docs.digicert.com/en/trust-lifecycle-manager/certificates/certificate-attributes-and-extensions/key-usage.html
            if cert.key_usage and (required_key_usage.intersection(cert.key_usage) != required_key_usage or
                                   not_required_key_usage.difference(cert.key_usage) != not_required_key_usage):
                continue

            matching_certificates.append(cert)
        return matching_certificates

    @staticmethod
    def sort_cas(unsorted_cas):
        """
        Sorts a list of CA certificates from the lowest Intermediate CA to the Highest one (Intermediate or Root).
        Expects a "perect" contiguous chain of CAs.
        Will raise exceptions for deviations:
            - multiple Root CAs or chains or lowest CAs
            - internal gaps
            - etc.

        Args:
            unsorted_cas: A list of Certificate objects

        Returns:
            A list of Certificate objects, sorted from the lowest Intermediate CA to the Highest (Intermediate or Root)

        Raises:
            Exception: if the input does not represent a perfect single CA chain/segment.
        """

        # Empty list
        if not unsorted_cas or len(unsorted_cas) == 0:
            return []

        # Check that the provided CAs are actually CA certificates
        for ca in unsorted_cas:
            if not ca.is_ca:
                raise Exception(f"CA chain contains a non-CA Certificate '{ca.subject.human_friendly}'")

        # List of one, already sorted, obviously
        if len(unsorted_cas) == 1:
            return unsorted_cas

        # Check for multiple Root CAs
        root_cas = []
        for ca in unsorted_cas:
            if ca.subject.dump() == ca.issuer.dump():
                root_cas.append(ca)

        if len(root_cas) > 1:
            raise Exception("CA chain contains more than one Root CA")

        # Map subjects to certs (easy lookup)
        subject_map = {ca.subject.dump(): ca for ca in unsorted_cas}

        # Get the subject of all certs that are issuers of others
        # The "start_ca" (lowest Intermediate CA) subject will NOT be in there
        higher_cas_subjects = set()
        for current_ca in unsorted_cas:
            for other_ca in unsorted_cas:
                if current_ca is not other_ca and current_ca.subject.dump() == other_ca.issuer.dump():
                    higher_cas_subjects.add(current_ca.subject.dump())
                    break

        # Get all the possible start_cas (lowest Intermediate CA of a chain)
        potential_start_cas = []
        for ca in unsorted_cas:
            if ca.subject.dump() not in higher_cas_subjects:
                potential_start_cas.append(ca)

        # Get the start_ca (we should have only one)
        start_ca = None
        if not potential_start_cas:
            raise Exception("No lowest Intermediate CA found in hte CA chain")
        elif len(potential_start_cas) > 1:
            raise Exception("Multiple lowest Intermediate CAs found in hte CA chain")
        else:
            start_ca = potential_start_cas[0]

        # Walk the chain from the lowest to the highest CA
        sorted_cas = []
        current_ca = start_ca

        while current_ca:
            sorted_cas.append(current_ca)

            # Check if we have reached the Root CA
            if current_ca.subject.dump() == current_ca.issuer.dump():
                break

            # Get the next CA in the chain
            next_ca = subject_map.get(current_ca.issuer.dump())
            if next_ca:
                current_ca = next_ca
            else:
                # All provided CAs are already added (i.e. no Root CA provided)
                if len(sorted_cas) == len(unsorted_cas):
                    break
                # We have found a gap in the CA chain
                else:
                    raise Exception(f"Gap in the CA chain: issuer of {current_ca.subject.human_friendly} not found")

        # Check if all provided CAs have been "consumed".
        # If not, probably because multiple chains were provided
        if len(sorted_cas) != len(unsorted_cas):
            raise Exception(f"Length mismatch: expected {len(unsorted_cas)} CAs but sorted {len(sorted_cas)}")

        return sorted_cas


class EnrollmentStatus:
    def __init__(self, fail_info=None, transaction_id=None, certificates=None, crl=None):
        if fail_info:
            self.status = PKIStatus.FAILURE
            self.fail_info = fail_info
        elif transaction_id:
            self.status = PKIStatus.PENDING
            self.transaction_id = transaction_id
        else:
            self.status = PKIStatus.SUCCESS
            self.certificates = certificates
            self.crl = crl
