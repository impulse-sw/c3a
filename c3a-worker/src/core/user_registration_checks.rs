use c3a_common::{AuthenticationFlow, AuthenticationFlowRequest, AuthenticationStep, AuthenticationStepRequest, SignUpOpts};
use cc_server_kit::prelude::*;

use crate::api::users::RegistrationStatePayload;

pub(crate) fn validate_authentication_flows(
  registration_state: RegistrationStatePayload,
  authentication_flows_reqs: &Vec<AuthenticationFlowRequest>,
  sign_up_opts: &SignUpOpts,
) -> MResult<Vec<AuthenticationFlow>> {
  let mut flows = vec![];
  
  for flow_req in authentication_flows_reqs {
    let mut flow = vec![];
    
    for step_req in flow_req {
      let step = match step_req {
        AuthenticationStepRequest::Password { password } => {
          
        }
      };
      flow.push(step);
    }
  }
  
  Ok(flows)
}
