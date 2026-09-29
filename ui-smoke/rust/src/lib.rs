use gloo_net::http::Request;
use serde::Serialize;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;
use yew::prelude::*;

#[derive(Serialize)]
struct Credentials { email: String, password: String }

#[function_component(App)]
fn app() -> Html {
    let email = use_state(String::new);
    let password = use_state(String::new);
    let result = use_state(String::new);

    let make_submit = |path: &'static str| {
        let email = email.clone();
        let password = password.clone();
        let result = result.clone();
        Callback::from(move |_| {
            let email = (*email).clone();
            let password = (*password).clone();
            let result = result.clone();
            spawn_local(async move {
                result.set("working…".into());
                let base = option_env!("SHARED_AUTH_BASE_URL").unwrap_or("http://127.0.0.1:8120");
                let req = Request::post(&format!("{base}{path}"))
                    .header("accept", "application/json")
                    .json(&Credentials { email, password });
                match req {
                    Ok(req) => match req.send().await {
                        Ok(resp) => {
                            let status = resp.status();
                            let body = resp.text().await.unwrap_or_default();
                            result.set(format!("{status} {body}"));
                        }
                        Err(err) => result.set(err.to_string()),
                    },
                    Err(err) => result.set(err.to_string()),
                }
            });
        })
    };

    html! {
      <main>
        <h1>{"Shared Auth smoke"}</h1>
        <input type="email" placeholder="Email" value={(*email).clone()}
          oninput={{
            let email = email.clone();
            Callback::from(move |event: InputEvent| {
              let input: HtmlInputElement = event.target_unchecked_into();
              email.set(input.value());
            })
          }} />
        <input type="password" placeholder="Password" value={(*password).clone()}
          oninput={{
            let password = password.clone();
            Callback::from(move |event: InputEvent| {
              let input: HtmlInputElement = event.target_unchecked_into();
              password.set(input.value());
            })
          }} />
        <button onclick={make_submit("/auth/register")}>{"Sign up"}</button>
        <button onclick={make_submit("/auth/login")}>{"Log in"}</button>
        <pre>{(*result).clone()}</pre>
      </main>
    }
}

#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn run() { yew::Renderer::<App>::new().render(); }
