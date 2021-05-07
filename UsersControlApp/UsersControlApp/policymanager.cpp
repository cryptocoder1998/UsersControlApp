#include "policymanager.h"

LSA_HANDLE PolicyManager::OpenPolicyHandle()
{
	LSA_OBJECT_ATTRIBUTES objectAttr;
	NTSTATUS status = 0x0;
	LSA_HANDLE policyHandle;

	LsaOpenPolicy_t myLsaOpenPolicy = (LsaOpenPolicy_t)GetProcAddress( moduleAdvApi_, "LsaOpenPolicy" );
	// Initializing objectattr to zeroes
	ZeroMemory(&objectAttr, sizeof(objectAttr));

	status = myLsaOpenPolicy( NULL, &objectAttr, 
		POLICY_ALL_ACCESS | POLICY_LOOKUP_NAMES, &policyHandle );
	
	/// ErrorStatus 0xC0000022 - STATUS_ACCESS_DENIED
	/// it must be executed using powershell in sudo
	if ( status != 0 )
	{
		BOOST_LOG_TRIVIAL(error) << "Policy handle wasn't opened, error: 0x" 
			<< std::hex << status;
		return NULL;
	}
	return policyHandle;
}

LSA_HANDLE PolicyManager::GetPolicyHandle() const
{
	return policyHandle_;
}