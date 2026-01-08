<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreScanRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true; // Publicly accessible
    }

    protected function prepareForValidation(): void
    {
        $url = $this->input('url');
        // Prepend https:// if protocol is missing
        if ($url && !preg_match("~^(?:f|ht)tps?://~i", $url)) {
            $this->merge(['url' => "https://" . $url]);
        }
    }

    public function rules(): array
    {
        return [
            'url' => 'required|url'
        ];
    }

    public function messages(): array
    {
        return [
            'url.required' => 'URL wajib diisi.',
            'url.url' => 'Format URL tidak valid.'
        ];
    }
}
